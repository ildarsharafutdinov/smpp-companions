---
baseline_commit: 815c16691ee117fcf32d9939dc52f1fd48401ff0
---

# Story 1.3: Config Fail-Fast Matrix (role × mode + TLS + secrets + AD-30)

Status: ready-for-dev

> Story 1.3 is the **LAST Epic 1 story** — it grows the `companion.*` config skeleton Story 1.1
> seeded (`ProxyCompanionProperties` + `application.yml` + two stub tests) into the EXHAUSTIVE
> startup fail-fast matrix: the AD-17 role×mode required/optional/FORBIDDEN grid, the Mode B
> reverse-only **warn + opt-in ack + start** posture, secret FILE-PATH validation (AD-18), the TLS
> floor + cipher intersection (AD-34/SEC-1), 1:1 routing (AD-29), AND the AD-30 config half Story 1.2
> explicitly DEFERRED to 1.3 — the `MaxDirectMemorySize` formula inputs, the `companion.*`
> MAX_COMMAND_LENGTH config key, and the **RELAY-026** three-way shared-constant assertion the codec
> stubbed. Completing 1.3 makes Epic 1 "done" and unblocks the linear DAG (the **Epic 2 opener is
> gated on Epic 1 completion**). ADs owned: **AD-17, AD-18, AD-26, AD-29, AD-30 (config half),
> AD-34, AD-35** (with AD-7/AD-11/AD-13/AD-16/AD-21 as constraints). This is TEA handoff **E1/S3**.

---

## ⚠️ Read first — ACs are NOT in epics.md; 6 decisions (fail-closed defaults below)

### 0. The ACs must be ASSEMBLED, not copied

`epics.md` (lines 416–433) leaves ALL stories as templated placeholders (`### Story {{N}}.{{M}}`), so
Story 1.3's concrete ACs are **NOT in epics.md**. They are assembled from three sources:

1. The sprint-status note (`sprint-status.yaml:55–56`): "role × mode fail-fast + Mode B ack + secret
   file-path checks + TLS-floor/cipher intersection (SEC-050..061/096/097)".
2. The SEC scenario catalog (`test-coverage-scenarios.md §4.7`): **SEC-050..061 + SEC-096/097** (all
   R17, P1, unit/integration-tier, Epic-1-owned) + **RELAY-026** (codec-deferred to 1.3).
3. The AD-30 config half Story 1.2 explicitly deferred (`1-2-smpp-3-4-codec.md:170–175,426–429`;
   `deferred-work.md:7,31–35`).

**Do NOT hunt epics.md for ACs. The ACs in this file ARE the authoritative set.**

### Decisions — proceed on the fail-closed default; surface to the user at dev-story if any feels wrong

Per the standing preference (fail-closed + simplicity), each fork below ships with a recommended
default. Proceed on it; the user may override.

- **D1 — AD-30 startup self-check timing.** AD-30 bundles TWO assertions: (1) the **static RELAY-026**
  one-constant scan, and (2) a **startup self-check** reading LIVE `MaxDirectMemorySize` via
  `ByteBufAllocatorMetric` ≥ the computed budget. The shared `PooledByteBufAllocator` (AD-21) + relay
  wiring land in **Epic 2** — they do not exist in 1.3. **Default: SPLIT — 1.3 ships the static
  RELAY-026 scan + the config inputs/formula NOW; DEFER the live `ByteBufAllocatorMetric` self-check
  to Epic 2** (when the allocator exists). Log the split to `deferred-work.md`.

- **D2 — AD-34 per-context cipher intersection.** AD-34 names "EVERY context (ingress server + every
  egress target + the IdP mTLS client context)" — those `SSLContext`s are built in **Epic 3**
  (`proxy/security/`, currently package-info-only). **Default: 1.3 ships the config-side TLS floor
  (SEC-061) + a config-time intersection against a JDK-default `SSLContext`'s supported suites**
  (proves the configured set is non-empty and JDK-supported); **DEFER the per-egress-context
  intersection to Epic 3** when those contexts exist. Do NOT half-build SSLContexts in config
  validation — that is the trap that pre-empts Epic 3's SEC-087/088/089 runtime vectors.

- **D3 — `companion.mode` default.** Adding `mode` as a required key **breaks the 1.1 seed tests**
  (`BootstrapLifecycleTest.builder()`, `CompanionRoleFailFastTest`, `CompanionTlsBindingTest`) which
  boot with only `--companion.role=forward`. **Default (fail-closed): NO default for `mode`** — require
  it explicitly (a default mode for a security product is itself a fork; fail-closed = no default).
  Update the 1.1 seed tests in lockstep (T6) to pass `--companion.mode=A`.

- **D4 — Matrix validator mechanism (the central design decision).** Field-level jakarta validation
  (`@NotNull`/`@Min`/`@URL`) CANNOT express the role×mode matrix ("forward+B forbidden", "reverse+A
  requires the client trust store"). **Default (simplest fail-closed): one class-level jakarta
  `@ConstraintValidator` on `ProxyCompanionProperties`** (fired by the existing `@Validated` on context
  refresh → non-zero exit), encoding the full AD-17 matrix + TLS floor + secret-path + trust-store
  checks. Prefer this over a separate `Validator` `@Component` or `@AssertTrue` methods: one mechanism,
  fires at the same bind-and-validate phase, simplest test slice.

- **D5 — SEC-050 trust-store validation depth.** SEC-050 demands the 5 deep states
  (absent/empty/wrong-format/wrong-password/zero-`trustedCertEntry`) — real
  `KeyStore.getInstance().load()` PKIX validation, not just AD-18 file existence. AD-13 is listed under
  Epic 3's Key ADs, but the handoff pins SEC-050 → E1 (R17). **Default (fail-closed): 1.3 ships the
  full `KeyStore`-load validation** in a config-adjacent validator (it is a startup config concern;
  wrong-password/zero-entries catches real misconfig a file-existence check misses). The runtime mTLS
  PKIX *path* stays Epic 3; 1.3 validates the trust *store* at bind time.

- **D6 — Exact `companion.*` key names.** AD-17 fixes the matrix *semantics*, AD-34 fixes the TLS
  *defaults*, AD-29 fixes the routing *value schema* `{host, port, tlsContextId?}` — but the YAML *key
  paths* are explicitly deferred ("application.yml exact keys — config detail"). **Default: the dev
  selects key names** (relaxed-binding-clean kebab-case under `companion.*`), records them in the Dev
  Agent Record + mirrors into `docs/` (AD-31), and the **green build (AC6) is the proof** — same
  discipline as 1.2/1.4 impl-selected versions.

> **Opportunistic, non-blocking:** the CODEC-026/029 planning-doc literal (`bind_transceiver = 0x0F`,
> the `ESME_RINVSYSID` status code — should be `0x09`) is still open in `deferred-work.md:36–40` from
> Story 1.2. 1.3 MAY correct `test-coverage-scenarios.md:221,241` at the next planning pass; it is not
> code-blocking.

---

## Story

**As a** proxy operator,
**I want** a `companion.*` configuration that refuses to start (non-zero exit, clear message) on any
ambiguous, insecure, or missing role×mode cell — and that starts Mode B reverse only after a loud
plaintext warning + explicit opt-in acknowledgment,
**so that** no insecure/ambiguous configuration can ever silently boot, the codec max and the
allocator budget can never drift, and Epic 2/3 can mount on a config layer whose fail-fast posture is
falsifiable by an exhaustive matrix rather than by the author's own claim.

---

## Acceptance Criteria

ACs are grouped; each maps to the TEA scenario IDs (`SEC-0xx`, `RELAY-026`) in
`_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md`, which carry the full
technique/tooling/notes. Implement every mapped scenario. **Every cell MUST bite** — see Dev Notes
"Make every assertion bite."

### AC1 — role × mode fail-fast matrix (AD-17, AD-29, AD-11)
Every `(role ∈ {forward, reverse}) × (mode ∈ {A, B, C})` cell has a deterministic startup outcome
(refuse / warn+ack+start / start). Implemented as a class-level `@ConstraintValidator` (decision D4).
- **forward × B is FORBIDDEN → refuse.** Maps: **SEC-051**.
- **reverse × B WITHOUT ack → refuse; reverse × B WITH ack → loud plaintext warning then START**
  (Mode B is reverse-only AND not refused — AD-17). Maps: **SEC-052** (two branches; capture the
  startup warning text via `OutputCaptureExtension`).
- **forward × A/C missing the server cert+key → refuse.** Maps: **SEC-056**.
- **reverse × C missing the client cert+key → refuse.** Maps: **SEC-057** (distinct from SEC-096).
- **forward with an empty/missing routing table → refuse** (AD-29 1:1; no default route per AD-11).
  Maps: **SEC-058**.
- **reverse (any mode) missing the SMSC endpoint → refuse.** Maps: **SEC-059**.
- **reverse × A missing the client trust store → refuse** (the SMSC/forward server-cert anchor; AD-26,
  never `cacerts`). Maps: **SEC-096** — pins the role×mode-specific cell SEC-050 leaves generic.
- **forward × A STARTS without an SMSC endpoint** (SMSC endpoint NOT required for forward — it forwards
  to the reverse proxy). POSITIVE complement of SEC-059. Maps: **SEC-097**.
- The required-config matrix (AD-17 table below) is encoded cell-by-cell; no silent accept.

### AC2 — TLS floor + cipher intersection (AD-34, SEC-1)
- **TLS floor ≥ 1.2:** protocols containing `SSLv3`/`TLSv1.0`/`TLSv1.1` → refuse. Maps: **SEC-061**.
- **Config-time cipher/protocol intersection:** intersect the configured set with a JDK-default
  `SSLContext`'s supported suites; empty intersection → refuse (AD-34). Per-egress-context intersection
  DEFERRED to Epic 3 (decision D2). The shipped AD-34 defaults (4 TLS-1.2 ECDHE-AES-GCM suites + 3
  TLS-1.3 AEAD suites, protocols `[TLSv1.3, TLSv1.2]`) stay byte-exact — `CompanionTlsBindingTest`
  pins them.

### AC3 — secrets as file paths + trust-store validation (AD-18, AD-13)
- **Secrets are FILE PATHS** (server cert/key, client cert/key, trust store, OIDC client cred) — never
  an env-var value. Missing OR unreadable (permissions/IO error) secret file → refuse. Parametrized
  over secret types. Maps: **SEC-060** (tmpfs/`@TempDir` fixtures; the unreadable-permission case must
  be deterministic across CI).
- **Trust-store 5-state validation:** absent/empty/wrong-format/wrong-password/zero-`trustedCertEntry`
  → refuse (AD-13). `KeyStore.getInstance().load()` exceptions (`UnrecoverableKeyException` for
  wrong-password, `IOException`) are caught and converted to a clean non-zero startup exit. Maps:
  **SEC-050**. (The trust store never falls back to JDK `cacerts` for ANY peer path.)

### AC4 — OIDC provider URL + ports (AD-12, AD-17)
- **OIDC provider URL scheme != https → refuse** (the proxy→provider link is HTTPS-only, AD-12/SEC-3).
  Maps: **SEC-053**.
- **OIDC provider URL absent → refuse — for forward (A/C)** (the forward role performs OIDC per
  AD-12; reverse does not — this is a matrix-cell specialization, see Dev Notes). Maps: **SEC-054**.
- **Bad/missing SMPP bind or SMSC ports** (out-of-range/negative/unset) → refuse. Maps: **SEC-055**.

### AC5 — AD-30 config half + RELAY-026 three-way constant (AD-30, R27)
- Wire the four AD-30 formula inputs into `companion.*`: `max_frame` (defaulting to / referencing
  `SmppFrame.MAX_COMMAND_LENGTH`), `max_inbound_depth`, `concurrent_pairs`, `safety_factor`, plus the
  `companion.*` MAX_COMMAND_LENGTH config key. The `MaxDirectMemorySize = max_frame ×
  max_inbound_depth × concurrent_pairs × safety_factor` formula is implemented (pure, unit-testable).
- **Promote RELAY-026** from the codec stub to the full three-way contract: **codec-constant
  (`SmppFrame.MAX_COMMAND_LENGTH` = 65536) ≡ formula input (`max_frame`) ≡ `companion.*` config
  default all reference ONE named constant** — asserted by a compile-time ArchUnit/AST reference scan
  in `proxy/src/test` (crosses the proxy→codec seam; CODEC-039 inward-only rule stays green). Maps:
  **RELAY-026** (integration/P1/R27). The live `ByteBufAllocatorMetric` startup self-check is DEFERRED
  to Epic 2 (decision D1).
- Clear the 1.3-bound `deferred-work.md` entries (AD-30 inputs, RELAY-026 stub, tls-null-guard).

### AC6 — green build + null-safety + EXTEND don't replace (AD-35, AD-7, AD-16)
- `./gradlew clean build :buildSrc:test` is GREEN on JDK 25 + `--enable-preview`. No test removed or
  `@Disabled` to make a gate pass.
- **Lockstep seed-test updates:** adding `mode` + other required fields breaks
  `BootstrapLifecycleTest.builder()`, `CompanionRoleFailFastTest.recordAcceptsValidRole`, and
  `CompanionTlsBindingTest` (they boot/construct with only `role`). Update them in lockstep (T6) so
  they keep testing lifecycle/binding, not the new required fields.
- Every new proxy/config main class is NullAway-clean at ERROR on `compileJava` (AD-35); every new
  config sub-package gets its own `@NullMarked package-info.java` (JSpecify does NOT propagate to
  sub-packages — Story 1.4 caught this). Genuinely-optional keys (e.g. forward+A has no SMSC endpoint)
  are explicitly `@Nullable`.
- **EXTEND, don't replace:** `ProxyCompanionProperties`, `application.yml`,
  `CompanionRoleFailFastTest`, `CompanionTlsBindingTest`, `MaxCommandLengthContractTest` are extended
  in place — the 1.1 role smoke + the AD-34 TLS-binding pin stay green. **Do NOT modify codec
  sources** (codec is DONE on master; 1.3 only REFERENCES `SmppFrame.MAX_COMMAND_LENGTH` across the
  inward-only seam). **Do NOT add a third Gradle module** (AD-7 fixes the count at two). **Do NOT
  enable any Spring web server** (`spring.main.web-application-type` stays `none`, AD-16).

---

## Tasks / Subtasks

- [ ] **T1 — Extend `ProxyCompanionProperties` + the matrix validator** (AC1, AC3, AC4)
  - [ ] Add `Mode` enum `{A, B, C}` (`@NotNull` — no default, decision D3); SMSC endpoint
        (`host`+`port`); SMPP bind port; OIDC provider URL; server cert+key paths; client cert+key
        paths; client trust-store path+password; the 1:1 routing table (AD-29: `system_id` allow-list
        → single egress `{host, port, tlsContextId?}`); the Mode B opt-in ack flag; the four AD-30
        memory inputs (`max_frame` referencing `SmppFrame.MAX_COMMAND_LENGTH`, `max_inbound_depth`,
        `concurrent_pairs`, `safety_factor`); and the `companion.*` MAX_COMMAND_LENGTH key.
  - [ ] Add `@Valid` on every nested record so bean validation cascades; **fix the deferred
        `tls`-absent NPE** (`deferred-work.md:10`) — `tls` and every nested record get null/absent
        protection so a missing block fails fast with a clear message, not an NPE.
  - [ ] Add the **class-level `@ConstraintValidator`** (decision D4) encoding the full AD-17 matrix:
        forward+B forbidden (SEC-051); reverse+B warn+ack+start (SEC-052); per-cell required config
        (SEC-056/057/058/059/096); forward+A no-SMSC-allowed positive (SEC-097); OIDC https/present
        for forward (SEC-053/054); port ranges (SEC-055); TLS floor (SEC-061); secret file
        existence+readability (SEC-060); trust-store 5-state (SEC-050); routing non-empty (SEC-058).
  - [ ] `@NullMarked package-info.java` for any new sub-package (validator/routing).
- [ ] **T2 — Extend `application.yml`** (AC1–AC5)
  - [ ] Add the new `companion.*` keys (decision D6 — dev selects kebab-case names; record in Dev
        Agent Record): `companion.mode`, `companion.oidc.*`, `companion.smsc.*`, `companion.bind.*`,
        secret paths, `companion.routing.*`, the Mode B ack flag, `companion.memory.*` (the AD-30
        inputs), `companion.max-command-length` (referencing the codec constant's value, 65536).
  - [ ] Keep verbatim: `spring.main.web-application-type: none` (AD-16), the 30s shutdown timeout,
        `companion.role: forward`, and the **entire `companion.tls.*` block** (AD-34 defaults —
        `CompanionTlsBindingTest` asserts `containsExactly` in order; any reorder/drop fails it).
- [ ] **T3 — Fail-fast matrix test suite** (AC1, AC3, AC4)
  - [ ] Promote `CompanionRoleFailFastTest` (or add a sibling matrix test) to the full
        SEC-050..061/096/097 suite — one parametrized cell per scenario, each driven through REAL
        Spring binding. Reuse `chainMessages()` + `ApplicationContextRunner` (slice) /
        `SpringApplicationBuilder` (full context) verbatim.
  - [ ] SEC-052: add startup-OUTPUT capture (`OutputCaptureExtension`) for the loud plaintext warning
        on the ack branch + refuse on the no-ack branch.
  - [ ] SEC-060: `@TempDir`/tmpfs file fixtures for the missing + unreadable-permission secret cases
        (deterministic; no root).
  - [ ] SEC-097: a POSITIVE (forward+A STARTS without SMSC) — assert the context does NOT fail.
  - [ ] Tag `@Tag("integration") @Tag("sec") @Tag("p1") + @DisplayName` (SEC-050..061/096/097 are
        P1; do NOT copy the seed tests' `p2` tag).
- [ ] **T4 — TLS floor + cipher intersection** (AC2)
  - [ ] SEC-061: protocols containing a sub-1.2 protocol → refuse.
  - [ ] AD-34 config-time intersection against a JDK-default `SSLContext`'s supported suites → empty
        → refuse (decision D2). Extend `CompanionTlsBindingTest` (keep the `containsExactly` pin).
- [ ] **T5 — AD-30 config half + RELAY-026 promotion** (AC5)
  - [ ] Implement the pure `MaxDirectMemorySize` budget formula (unit-testable).
  - [ ] Promote `MaxCommandLengthContractTest` + add the proxy-side ArchUnit/AST three-way assertion
        (codec-constant ≡ formula-input ≡ config-default → ONE named constant). Reference
        `smpp.companion.codec.framer.SmppFrame.MAX_COMMAND_LENGTH` (NOT `SmppCommandIds` — see
        gotchas).
  - [ ] Log the live `ByteBufAllocatorMetric` self-check DEFERRAL to Epic 2 in `deferred-work.md`
        (decision D1); clear the AD-30-inputs + RELAY-026-stub + tls-null-guard entries.
- [ ] **T6 — Lockstep seed-test updates + green build** (AC6)
  - [ ] Update `BootstrapLifecycleTest.builder()`, `CompanionRoleFailFastTest.recordAcceptsValidRole`,
        and `CompanionTlsBindingTest` to pass `--companion.mode=A` (+ any other newly-required field)
        so they keep testing lifecycle/binding.
  - [ ] Full `./gradlew clean build :buildSrc:test` GREEN; CODEC-039/040/041 + AD-35 + OBS-013 +
        SEC-099 stay green; no `// FIXME` markers left.

### Review Findings

_(Filled by `code-review` after dev-story.)_

---

## Dev Notes

### What already exists (from Stories 1.1 + 1.2 + 1.4) — EXTEND, don't replace

- **`proxy/.../config/ProxyCompanionProperties.java`** — `@ConfigurationProperties("companion")
  @Validated` record with exactly two components: `@NotNull Role role` (enum `FORWARD`/`REVERSE`) and
  `@Valid Tls tls` (nested record: `protocols`, `tls12CipherSuites`, `tls13CipherSuites`). Only `role`
  is fail-fast-guarded today. The class javadoc literally says *"The exhaustive role×mode fail-fast
  matrix is Story 1.3; this story ships the single companion.role refuse-to-start smoke (AC9)."* —
  1.3 fulfills that contract. KEEP the `@ConfigurationProperties("companion")` prefix, `@Validated`,
  the `Role` enum values, the `Tls` record + its exact AD-34 lists, and `@NullMarked` (AD-35).
- **`proxy/src/main/resources/application.yml`** — `spring.main.web-application-type: none` (AD-16),
  `spring.lifecycle.timeout-per-shutdown-phase: 30s`, `companion.role: forward`, and the AD-34
  `companion.tls.*` defaults. KEEP the `spring.*` keys + the entire `companion.tls.*` block verbatim.
- **`proxy/.../config/CompanionRoleFailFastTest.java`** — 3 seed tests + the **`chainMessages(Throwable)`
  cause-chain walker** (Spring wraps `ConversionFailedException`/`BindException` deeply — a bare
  `isInstanceOf` passes on UNRELATED wiring failures; the helper walks the chain and `anyMatch`es on
  the offending property). KEEP it; reuse for every matrix cell.
- **`proxy/.../config/CompanionTlsBindingTest.java`** — boots the REAL context (so `application.yml`
  is the property source) and `containsExactly`-pins the AD-34 cipher/protocol lists IN ORDER. KEEP;
  it is the regression gate for AD-34 default drift.
- **`codec/.../framer/SmppFrame.java`** — `MAX_COMMAND_LENGTH = 65536` (+ `HEADER_LENGTH=16`,
  `MIN_COMMAND_LENGTH=16`). Javadoc: *"from Story 1.3 it is the single input to the relay direct-memory
  formula and the config default — one named value so codec max and allocator budget cannot drift."*
  1.3 REFERENCES it; **does NOT modify it** (codec is DONE; AD-7 inward-only).
- **`codec/.../command/MaxCommandLengthContractTest.java`** — RELAY-026 STUB: pins
  `SmppFrame.MAX_COMMAND_LENGTH == 65536 == 0x00010000`. 1.3 PROMOTES it (+ a proxy-side three-way
  assertion); KEEP the codec-side pin.
- **`proxy/.../bootstrap/ProxyCompanionLifecycle.java`** — framework-only `SmartLifecycle` stub
  (`@Component`); the AD-22 7-step shutdown BODY is Epic 4. 1.3 generally does NOT touch it; prefer
  bean-validation fail-fast over a new `SmartLifecycle` (a second `SmartLifecycle` activates the
  phase-ordering gotcha).
- **`proxy/build.gradle.kts`** — Spring Boot 4.1.0, `spring-boot-starter` +
  `spring-boot-starter-validation` (**jakarta validation IS on the classpath** — the fail-fast
  mechanism depends on it), jspecify 1.0.0, netty-bom 4.2.16, nimbus-jose-jwt 10.9.1, micrometer,
  `project(:codec)`. Test: `spring-boot-starter-test` (provides `OutputCaptureExtension`),
  `archunit-junit5 1.4.2`. **1.3 needs NO new dependencies** — validation, config binding, the codec
  constant, and ArchUnit are all already present. Do NOT add spring-web/webflux/actuator (AD-16).

### The AD-17 role × mode required-config matrix (encode this cell-by-cell)

| | Mode A (one-way TLS) | Mode B (plaintext, **reverse-only**) | Mode C (mTLS) |
|---|---|---|---|
| **forward** | server cert+key; routing table; OIDC provider; **SMSC NOT required** | **FORBIDDEN** (SEC-051) | server cert+key + trust store; routing table; OIDC provider |
| **reverse** | client trust store (AD-26, **never `cacerts`**); SMSC endpoint | opt-in ack + SMSC endpoint (**warn + ack + START**, SEC-052) | client cert+key + trust store; SMSC endpoint |

TLS floor: TLS 1.2 min, 1.3 preferred. Bad ports / unset provider URL / non-`https` provider URL →
refuse. Trust-store validation per AD-13 (5 states).

### Architecture compliance (the binding ADs)

- **AD-17** — startup fail-fast + role×mode matrix + Mode B posture (the matrix above). [SPINE:163–173]
- **AD-18** — secrets are FILE PATHS (never env-var values; fail-fast on missing/unreadable). [SPINE:175–178]
- **AD-26 / AD-13** — the trust store NEVER falls back to JDK `cacerts` for any peer path; refuse on
  absent/empty/wrong-format/wrong-password/zero-`trustedCertEntry`. [SPINE:143–146, 215–218]
- **AD-29 / AD-11** — v1 routing is 1:1 (one carrier egress); routing table = `system_id` allow-list →
  the single egress `{host, port, tlsContextId?}`; a `system_id` not in the table → DENY (no default
  route). [SPINE:230–233, 130–133]
- **AD-30** — `MaxDirectMemorySize = max_frame × max_inbound_depth × concurrent_pairs ×
  safety_factor`; codec max (65536) ≡ formula input ≡ config default reference ONE constant (RELAY-026,
  static scan); live `ByteBufAllocatorMetric` self-check ≥ budget (DEFERRED to Epic 2, D1). [SPINE:235–238]
- **AD-34 / SEC-1** — the pinned cipher/protocol allowlist default ships in config; per-context empty
  intersection → fail-fast (config-time in 1.3, per-context in Epic 3, D2). [SPINE:259–262]
- **AD-7** — codec is PURE; dependency direction is strictly `proxy → codec`. 1.3 config code READS
  `SmppFrame.MAX_COMMAND_LENGTH`; it must NOT push config types into the codec. The RELAY-026 scan
  verifies the one-way reference. [SPINE:97–106]
- **AD-16** — Spring Boot owns externalized config (`@ConfigurationProperties` + relaxed binding +
  fail-fast); NO web server on the SMPP path (`web-application-type: none`). [SPINE:158–161]
- **AD-35** — NullAway at ERROR on `compileJava` (JSpecify `@NullMarked`). [SPINE:264–267]

### Library / framework requirements (exact versions)

| Component | Version | Role |
|---|---|---|
| JDK | 25 (+`--enable-preview` process-wide) | runtime/compile. 1.3 uses NO preview APIs. |
| Spring Boot | 4.1.0 (`proxy/build.gradle.kts`) | `@ConfigurationProperties` + relaxed binding + `@Validated` fail-fast + lifecycle |
| spring-boot-starter-validation | (transitive of SB 4.1.0) | jakarta validation (`@NotNull`/`@Min`/`@Max`/`@URL`/class-level `@ConstraintValidator`) — already on classpath |
| JSpecify | 1.0.0 (`compileOnly`) | `@NullMarked` / `@Nullable` (AD-35) |
| ArchUnit | 1.4.2 (`testImplementation`) | the RELAY-026 three-way static/AST assertion |
| spring-boot-starter-test | (transitive) | `ApplicationContextRunner`, `SpringApplicationBuilder`, `OutputCaptureExtension`, AssertJ |
| SmppFrame.MAX_COMMAND_LENGTH | codec constant (65536) | the single named formula input (REFERENCED, not duplicated) |

Versions not pinned in the architecture are impl-selected; **the green build (AC6) is the mutual-compat
proof** — same discipline as Story 1.2/1.4. The Spring Boot config-binding + validation + test-slice
patterns are **proven in-repo on SB 4.1.0** by the 1.1 seed tests; follow them.

### File structure requirements

- MAIN: extend in place — `proxy/.../config/ProxyCompanionProperties.java` (+ nested records),
  `proxy/.../resources/application.yml`. A new validator sub-package (if used) gets its own
  `@NullMarked package-info.java`.
- TEST: extend in place — `proxy/.../config/CompanionRoleFailFastTest.java`,
  `CompanionTlsBindingTest.java`; add the proxy-side RELAY-026 three-way assertion in
  `proxy/src/test` (it crosses the proxy→codec seam). PROMOTE (do not rewrite)
  `codec/.../command/MaxCommandLengthContractTest.java` — keep its codec-side pin.
- NO codec source changes. NO third module. NO web starter.

### Testing requirements / patterns to reuse

- **`chainMessages(Throwable)` cause-walk** (`CompanionRoleFailFastTest`) — every refusal assertion
  walks the Spring cause chain and matches on the failing property name. A bare
  `isInstanceOf(Exception.class)` is the false-confidence anti-pattern Story 1.1 review expelled.
- **`ApplicationContextRunner`** for cell-by-cell matrix slices (lighter); **`SpringApplicationBuilder
  (...).web(NONE).run("--companion.x=y")`** for full-context refusals that read `application.yml` as
  the property source.
- **`OutputCaptureExtension`** (SEC-052/064) for the loud plaintext warning — a NEW technique vs the
  existing catch-`Throwable`/`hasFailed` style.
- **`@TempDir`/tmpfs fixtures** (SEC-060) for missing + unreadable-permission secret files
  (deterministic, no root, CI-portable).
- **Make every assertion bite** — the load-bearing lesson from 1.2's seven review passes (the
  vacuous-assertion anti-pattern, CODEC-010/011/022). Each SEC-0xx cell must inject the EXACT bad
  config value through real Spring binding so a regression that silently SKIPS the check turns the test
  red. A "remove this check → test now passes" mutation control is the proof it bites.
- **Tagging**: `@Tag("integration") @Tag("sec") @Tag("p1") + @DisplayName` (SEC-050..061/096/097 are
  P1; do NOT copy the seed tests' `p2`). No `Thread.sleep`; deterministic only; no no-op tests.

### Previous-story intelligence

- **Story 1.1** seeded the `companion.*` skeleton and explicitly DEFERRED to 1.3: the whole role×mode
  matrix, the AD-30 config inputs (`max_frame`/`max_inbound_depth`/`concurrent_pairs`/`safety_factor`
  — none appear in `application.yml` today), and the `tls`-absent null guard
  (`deferred-work.md:7,10`). The 1.1 anti-pattern note warns against refusing Mode B at startup.
  [1-1-…md:95,136–145,151,206]
- **Story 1.2** (the model story — study its depth) shipped the codec half of AD-30
  (`SmppFrame.MAX_COMMAND_LENGTH = 65536`) and the RELAY-026 stub documenting the three-way contract
  1.3 completes. Its dominant lesson: **vacuous assertions** (CODEC-010/011/022) — every fail-fast
  matrix cell must bite. It also left the CODEC-026/029 `0x0F→0x09` planning-doc literal open
  (`deferred-work.md:36–40`) — opportunistic for 1.3. [1-2-…md:170–175,363–378,508–511]
- **Story 1.4** wired the AD-35 NullAway-at-ERROR gate (on `compileJava` + `compileJmhJava`); it caught
  a missed `@NullMarked` sub-package at the proxy root — **every new config sub-package needs its own
  `@NullMarked package-info.java`**.
- **Git ritual**: commit-message `feat(config): Story 1.3 …` (+ per-AC evidence body, footer
  `Co-Authored-By: Claude <noreply@anthropic.com>`); linear history on `master`; **branch per story**
  — 1.3 work lands on `story-1.3-config-matrix` (already cut from `master` @ `815c166`); on completion,
  "flip the story" = FF-merge to `master` + delete the branch.

### Latest technical information

- The Spring Boot 4.1.0 `@ConfigurationProperties` + `@Validated` + relaxed-binding + fail-fast pattern
  is **proven in-repo** by the 1.1 seed tests (`CompanionRoleFailFastTest`, `CompanionTlsBindingTest`).
  Follow it; do not introduce a parallel config mechanism.
- **Cross-field/cross-record matrix validation** needs a class-level jakarta
  `@ConstraintValidator` (decision D4) — field-level `@NotNull`/`@Min` cannot express "forward+B
  forbidden". One class-level constraint, fired by the existing `@Validated`, is the simplest fail-closed
  mechanism.
- The `companion.tls.*` relaxed binding (camelCase record ↔ kebab-case yml) is drift-pinned by
  `CompanionTlsBindingTest`; new keys follow the same convention and should get the same real-context
  bind assertion (not inspection-only — the 1.1 review expelled inspection-only TLS binding).

### Project Structure Notes

- Aligns with the two-module inward-only seam (AD-7): 1.3 lives in `proxy/config/` (+ the proxy-side
  RELAY-026 test); it references `SmppFrame.MAX_COMMAND_LENGTH` one-way across `proxy → codec`.
- **Out of scope** (do NOT do in 1.3): `relay/` splice/coupling (Epic 2); TLS/OIDC/JWKS/ROPC runtime
  (`proxy/security/`, Epic 3 — including SEC-087/088/089 runtime TLS vectors and the AD-30 live
  `ByteBufAllocatorMetric` self-check); AD-22 7-step shutdown body (Epic 4); the docs runbook surface
  (AD-31, Epic 6 — 1.3 owns the Mode B warning STRING emitted at startup, not the docs mirror);
  AD-32/AD-33 `_resp` synthesis + deny-code pinning (Epic 2/3); the AD-26 `cacerts` opt-in + Mode A
  ACL-isolation (SEC-063/064 — adjacent; ride along ONLY via the shared warn+ack mechanism, do not
  pull the Mode-A-specific warning/doc/scan into 1.3's AC set).

### References

- Epic 1 goal + packages: `epics.md:347–355`; sprint note `sprint-status.yaml:55–56`; cross-epic gates
  `sprint-status.yaml:57–61` (Epic-2 opener gated on E1; Story 3.1 ROPC probe parallel-eligible).
- Config ADs: `ARCHITECTURE-SPINE.md` AD-17(:163–173), AD-18(:175–178), AD-26(:215–218),
  AD-13(:143–146), AD-29(:230–233), AD-11(:130–133), AD-30(:235–238), AD-34(:259–262), AD-16(:158–161),
  AD-7(:97–106), AD-35(:264–267).
- AC scenario catalog: `test-coverage-scenarios.md §4.7` SEC-050..061/096/097 (:762–834),
  RELAY-026 (:471–475); risk map `smpp-companions-handoff.md:91,98,101` (R7/R17/R27).
- Prior stories: `1-1-…md` (skeleton + deferrals), `1-2-…md` (codec + AD-30 codec half + RELAY-026
  stub + vacuous-assertion lesson), `1-4-…md` (null-safety gate).
- Deferred to 1.3: `deferred-work.md:7` (AD-30 inputs), `:10` (tls null guards), `:31–35` (RELAY-026
  stub), `:36–40` (0x0F→0x09 planning literal).
- Existing skeleton: `proxy/.../config/ProxyCompanionProperties.java`, `application.yml`,
  `CompanionRoleFailFastTest.java`, `CompanionTlsBindingTest.java`,
  `codec/.../command/MaxCommandLengthContractTest.java`, `codec/.../framer/SmppFrame.java`.

---

## Dev Agent Record

### Agent Model Used

_(filled at dev-story)_

### Debug Log References

_(filled at dev-story)_

### Completion Notes List

_(filled at dev-story)_

### File List

_(filled at dev-story)_
