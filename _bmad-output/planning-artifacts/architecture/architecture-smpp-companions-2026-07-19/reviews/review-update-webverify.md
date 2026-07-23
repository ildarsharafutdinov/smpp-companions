# Web-Verification Review — Companions v1 UPDATE (2026-07-23)

- **Reviewer:** WEB-VERIFICATION (web-reality-check lens)
- **Date verified:** 2026-07-23
- **Scope:** the UPDATE that resolved test-design blockers Q1–Q7 — NEW ADs **AD-32, AD-33, AD-34** and the amended **AD-3, AD-19, AD-24, AD-25, AD-27, AD-30** + Accepted-Risk Register additions. The previously-finalized spine (AD-1..AD-31, passed 2-round 8+2-lens gate on 2026-07-19) is **NOT** re-reviewed here.
- **Method:** every load-bearing factual claim in the UPDATE (SMPP 3.4 `command_status`/`command_id` semantics, the `_resp` convention, `submit_sm_resp` body rules, `generic_nack` §4.3 reservation; the TLS-1.2 cipher allowlist in AD-34; the jcstress/ArchUnit/BlockHound tool fit) was checked against primary/authoritative sources as of 2026-07.
- **Verdict:** **PASS-WITH-FINDINGS.** Every headline factual value in the UPDATE is **CONFIRMED** — no item is mis-named, out-of-date, or wrong-valued. Three precision/conformance findings, all localized to AD-32's error/`generic_nack` path (one medium, two low); none breaks the architecture. The factual core of the UPDATE is sound.

---

## 1. Verified-accurate table

| UPDATE claim (location) | Verified against (2026-07) | Result |
| --- | --- | --- |
| **`ESME_RINVBNDSTS` == `0x00000004`**, "Incorrect BIND Status for given command", PDU sent in wrong session state (AD-32 case 3) | smpp.org error-code table: `0x00000004` = ESME_RINVBNDSTS = "Incorrect BIND Status for given command … PDU has been sent in the wrong session state." | ✅ Accurate value + semantics. |
| **`ESME_RINVCMDID` == `0x00000003`**, "Invalid Command ID" (AD-32 case 5) | smpp.org: `0x00000003` = ESME_RINVCMDID = "Invalid Command ID". | ✅ Accurate. |
| **`generic_nack` `command_id` == `0x80000000`**, RESERVED (§4.3) for unknown `command_id` / invalid `command_length` (AD-32 case 5) | SMPP 3.4 Issue 1.2 §4.3 GENERIC_NACK: `0x80000000`, returned for unrecognized command **and** invalid `command_length`; OpenMarket + OpenSMPP `Session.java` agree. | ✅ Accurate (see WV-2/WV-3 — the spine implements only the unknown-`command_id` half). |
| **Response `command_id` = request `command_id \| 0x80000000`** (bit 31 set) (AD-32 case 3) | SMPP 3.4 Table 5-1: `submit_sm 0x00000004 → submit_sm_resp 0x80000004`; `enquire_link 0x00000015 → enquire_link_resp 0x80000015`; `unbind 0x00000006 → unbind_resp 0x80000006`. | ✅ Accurate convention + values. |
| **`submit_sm_resp` mandates a `message_id` C-octet-string body field** (AD-32 case 3 example) | SMPP 3.4 Table 4-11: `message_id` = C-octet string, max 65 octets, **mandatory** *on success*. **BUT** "The `submit_sm_resp` PDU Body is not returned if the `command_status` field contains a non-zero value." | ✅ True for ROK; ❌ inverted for the error path case 3 actually uses — see **WV-1**. |
| **`enquire_link` permitted pre-couple / in OPEN-UNBOUND** (AD-32 case 2) | SMPP 3.4 §4.11 state table + Melrose Labs: `enquire_link` valid in OPEN, BOUND_TX/RX/TRX, UNBOUND. | ✅ Accurate. |
| **`unbind`/`unbind_resp` pre-couple = clean handshake, NOT a violation** (AD-32 case 1, AD-3 corollary) | SMPP 3.4: `unbind` valid in OPEN/BOUND/UNBOUND; `unbind_resp(ROK)` is the prescribed teardown. | ✅ Accurate. |
| **TLS-1.2 GCM suite names** (AD-34): `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `…_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `…_AES_128_GCM_SHA256` | Oracle "Java Security Standard Algorithm Names" JSSE cipher-suite table; OpenJDK `CipherSuite.java`. All four are standard, default-enabled names. | ✅ Valid / current. |
| **`TLS_ECDHE_*_WITH_CHACHA20_POLY1305_SHA256` "optional where the provider offers it"** (AD-34) | OpenJDK **JDK-8269299** (CSR JDK-8204192, delivered JDK 12, RFC 7905): JSSE ships `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` + `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` in the default-enabled collection. The hedge is exactly right (provider-dependent). | ✅ Accurate; hedge well-placed. |
| **"No CBC / no static-RSA / no RC4/3DES/null/anon" = correct 2026 posture** (AD-34) | OWASP TLS Cheat Sheet + Mozilla/TLSRef (WSTG): TLS-1.2 should be AEAD-only (GCM/ChaCha20) + ECDHE (forward secrecy); explicitly exclude CBC, RSA key-exchange, NULL/anon-DH, <128-bit. | ✅ Correct conservative posture. (AD-34 correctly does NOT conflate `ECDHE_RSA` auth with static-RSA key exchange.) |
| **`protocols ["TLSv1.3","TLSv1.2"]`, empty provider-intersect → fail-fast** (AD-34) | Standard JSSE `SSLParameters.setProtocols`/`setCipherSuites`; fail-fast on empty intersection is sound. | ✅ Sound. |
| **jcstress** — cross-thread visibility/happens-before races (AD-24) | OpenJDK `github.com/openjdk/jcstress`, `org.openjdk.jcstress:jcstress-core` on Maven Central. | ✅ Exists; fits stated use. |
| **ArchUnit** — module-boundary / one-constant assertion (AD-30) | `archunit.org`; `com.tngtech.archunit` — package/dependency rules, `FreezingArchRule`. | ✅ Exists; fits. (Precision note §3: "assert three sites reference ONE constant of value 65536" is more naturally a reflection-based JUnit test; the spine's "ArchUnit/Gradle" hedge covers this.) |
| **BlockHound** — event-loop-blocking detection (lens-listed; AD-4 invariant) | `github.com/reactor/BlockHound` (Project Reactor), 1.0.x active — Java agent that flags blocking calls on non-blocking threads. | ✅ Exists; fits event-loop-blocking detection. **Adopted in the test-design layer** (RELAY-018/019, risk R28, `test-design-qa.md`), not re-stated in the spine — appropriate division. |

---

## 2. Findings

### FINDING WV-1 — AD-32 case 3 synthesizes a *body* on a non-zero `command_status` `_resp`; SMPP 3.4 says omit the body · **medium**

**Where:** AD-32 case 3 — *"… `command_status = ESME_RINVBNDSTS (…)`, `sequence_number = offender.sequence_number`, and a **spec-conformant body** synthesized from a `command_id → response-body-requirement` lookup (e.g. `submit_sm_resp.message_id` as an empty C-octet string)…"*; the same "spec-conformant body" phrase is load-bearing for the AD's claim to be "SMPP 3.4-conformant."

**What the web shows:** SMPP 3.4 Table 4-11 (and the general PDU-body rule) states verbatim — *"The `submit_sm_resp` PDU Body is **not returned** if the `command_status` field contains a non-zero value."* This is a **universal SMPP convention**: any `_resp` carrying a non-zero `command_status` is header-only (16 octets), no body. `message_id` is mandatory **only** on the success (`ESME_ROK`) path; Wikipedia/Handwiki flag this as the spec's well-known "unfortunate note."

**Why it matters:** AD-32 case 3 synthesizes an **error** response (`ESME_RINVBNDSTS`, non-zero). For that path the spec-conformant body is **none** (zero length, `command_length == 16`), not "an empty C-octet string" (which is a 1-byte `0x00` and makes `command_length == 17`). So:
- the `command_id → response-body-requirement` lookup is **unnecessary on the error path** (no `_resp` carries a body when `command_status != 0`);
- the `submit_sm_resp.message_id` example is the body for a *success* response, mis-applied to an error response — it inverts the rule the lens asked to confirm.

Practical wire impact is near-zero (the connection is closed immediately after `writeAndFlush`), but (a) the AD's identity is explicit SMPP-3.4 conformance and this is a self-inconsistency in that argument, and (b) AD-24 mandates **authoring a from-scratch conformance suite** whose golden vectors could encode the wrong expectation (body present on error) or, conversely, flag the synthesized null byte as a malformation.

**Suggested fix:** for the non-zero error path, emit **header-only** (`command_length = 16`, no body); drop the body-requirement lookup for case 3 (it would only be relevant for an `ROK` synthesis, which case 3 never produces). Reword the example to: *"`command_status` is non-zero ⇒ no PDU body is returned (SMPP 3.4 Table 4-11); the offender's body is never parsed."*

Sources: <https://smpp.org/SMPP_v3_4_Issue1_2.pdf> (Table 4-11, §4) · <https://en.wikipedia.org/wiki/Short_Message_Peer-to-Peer> · <https://www.slideshare.net/slideshow/smpp-v3-4/8083215>

---

### FINDING WV-2 — AD-32 case 5 routes invalid `command_length` to a silent AD-30 drop+close, omitting the `generic_nack(ESME_RINVCMDLEN)` that §4.3 prescribes · **low**

**Where:** AD-32 case 5 — *"`generic_nack` is RESERVED for this (SMPP 3.4 §4.3): unknown `command_id` → `generic_nack(ESME_RINVCMDID …)` + close; **invalid length → AD-30 drop + close**."*

**What the web shows:** §4.3 GENERIC_NACK is prescribed for **two** unresolvable cases: unknown `command_id` → `ESME_RINVCMDID (0x00000003)`; **and** invalid `command_length` → `ESME_RINVCMDLEN (`0x00000002`)**. AD-32 emits the `generic_nack` for the first but not the second (length errors inherit AD-30's "drop + close," no nack). The spine therefore **cites §4.3 to justify one half while silently departing from it on the other** — an internal asymmetry newly visible because case 5 is the one place the AD invokes §4.3.

**Why it matters little:** an invalid `command_length` means the receiver has **lost stream synchronization**, so closing is mandatory regardless; a `generic_nack` before close is of limited diagnostic value. The choice is defensible — but it should be stated as an **above-spec fail-closed product policy** (exactly as the close-on-violation policy in AD-25/AD-32 is), not left reading as "§4.3-conformant." Note the length-drop behavior itself originates in the prior AD-30 (not new); only the §4.3 citation makes the asymmetry an UPDATE-level concern.

**Suggested fix (either):** (a) emit `generic_nack(ESME_RINVCMDLEN 0x00000002, seq = offender-seq-where-parseable)` + close for the length case to be fully §4.3-conformant; or (b) add a one-line note: *"invalid `command_length` ⇒ stream desynchronized ⇒ drop + close with no `generic_nack` (above-spec fail-closed; §4.3's `RINVCMDLEN` nack is intentionally suppressed because the frame boundary is untrustworthy)."*

Sources: <https://smpp.org/SMPP_v3_4_Issue1_2.pdf> §4.3 · <https://github.com/OpenSmpp/opensmpp/blob/master/core/src/main/java/org/smpp/Session.java> · <https://docs.aerialink.net/api/smpp/smpp-status-codes/>

---

### FINDING WV-3 — AD-32 case 5 sets `generic_nack` `sequence_number = 0` for unknown `command_id`; §4.3 says echo the offender's seq "where possible" (it is parseable here) · **low**

**Where:** AD-32 case 5 — *"unknown `command_id` → `generic_nack(ESME_RINVCMDID 0x00000003, sequence_number = 0)` + close."*

**What the web shows:** §4.3 / §3.2 direct that `generic_nack` should echo the offending PDU's `sequence_number` **where possible**. The SMPP header is fixed-layout (`command_length`|`command_id`|`command_status`|`sequence_number`, 4 octets each); for an unknown `command_id` whose `command_length` is valid (≥ 16 — the case in which you can identify it as "well-formed-but-unknown" rather than "corrupt length"), the `sequence_number` (octets 12–15) **is parseable**, so the echo is expected. `seq = 0` is the correct fallback **only** when the header itself is unparseable (the lost-sync / `command_length < 16` case, which AD-30 owns).

**Why it matters little:** the connection closes immediately regardless, and many real SMSCs use `seq = 0` on `generic_nack`. It is a minor conformance imprecision, not a wire-breaker.

**Suggested fix:** echo the offender's `sequence_number` for the unknown-`command_id`-with-valid-length case; reserve `seq = 0` for genuinely unparseable headers.

Sources: <https://smpp.org/SMPP_v3_4_Issue1_2.pdf> §3.2, §4.3 · <https://www.openmarket.com/docs/Content/apis/v4smpp/genericnack-examples.htm>

---

## 3. Things explicitly checked and found NOT to be problems

- **AD-33 wire collapse (ESME_ROK vs one generic denial code)** — no spec-level factual claim to refute; the design choice (collapse all denials to one wire code) is consistent with SMPP allowing an arbitrary non-zero `command_status` in `bind_*_resp`. Exact code deferred to the owning story — nothing to web-verify yet.
- **AD-34 TLS-1.3 cipher suites not enumerated** — TLS 1.3 suites (`TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`) are all AEAD + mandatory-forward-secret, so there is no weak TLS-1.3 suite to exclude; leaving them to the provider default is safe. Pinning them would be marginally more explicit but is not required.
- **`ESME_RALYBND (0x00000005)` not chosen for case 3** — correct. `RALYBND` = "Already in Bound State" (a second bind while bound); case 3 is the *opposite* (non-bind PDU while **not** bound), for which `RINVBNDSTS` is the right code.
- **AD-19 "command_id only in TRACE via `ByteBuf.getInt(4)`"** — the offset is correct (SMPP header: octets 0–3 = `command_length`, 4–7 = `command_id`); `getInt(4)` reads `command_id`. No codec helper ⇒ AD-7 inward-only preserved. Accurate.
- **BlockHound** — confirmed real and fit (reactor/BlockHound, 1.0.x). It is **not** re-stated in the spine but is a first-class tool in the test-design layer (RELAY-018/019 positive control + clean-hot-path, risk R28, `test-design-qa.md`), with the AD-4 "no blocking on the event loop" invariant mechanically asserted there. Appropriate division; no gap.
- **ArchUnit "shared-constant assertion" (AD-30)** — ArchUnit's sweet spot is dependency/structure rules (AD-7 inward-only, AD-27 codec ownership); asserting *numeric value equality* (65536 == formula input == config default) across three sites is more naturally a reflection-based JUnit test. The spine hedges this as "an ArchUnit/**Gradle** static test," so it is not wrong — only slightly off-tool. Non-blocking.
- **jcstress "experimental" label** — its own README calls it an experimental harness; it is nonetheless the de-facto standard for JVM memory-model/happens-before validation and is correctly scoped (nightly, cross-thread state only) in AD-24.

---

## 4. Sources (primary, cited inline above)

- SMPP 3.4 spec (Issue 1.2) — <https://smpp.org/SMPP_v3_4_Issue1_2.pdf> (§3.2 header, §4.3 GENERIC_NACK, §4.11 state table, Table 4-11 submit_sm_resp, Table 5-1 command IDs)
- SMPP error codes — <https://smpp.org/smpp-error-codes.html>
- SMPP command semantics — <https://melroselabs.com/docs/reference/smpp/enquire_link/> · <https://www.openmarket.com/docs/Content/apis/v4smpp/genericnack-examples.htm> · <https://github.com/OpenSmpp/opensmpp/blob/master/core/src/main/java/org/smpp/Session.java> · <https://en.wikipedia.org/wiki/Short_Message_Peer-to-Peer>
- Java JSSE cipher names — <https://docs.oracle.com/en/java/javase/24/docs/specs/security/standard-names.html> · <https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/ssl/CipherSuite.java>
- ChaCha20-Poly1305 in JSSE — <https://bugs.openjdk.org/browse/JDK-8269299> (CSR JDK-8204192; JDK 12+; RFC 7905 / RFC 8446)
- TLS posture — OWASP TLS Cheat Sheet <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html> · Mozilla/TLSRef <https://wiki.mozilla.org/Security/Server_Side_TLS> · OWASP WSTG weak-TLS testing
- Tooling — jcstress <https://github.com/openjdk/jcstress> · ArchUnit <https://www.archunit.org/userguide/html/000_Index.html> · BlockHound <https://github.com/reactor/BlockHound>
