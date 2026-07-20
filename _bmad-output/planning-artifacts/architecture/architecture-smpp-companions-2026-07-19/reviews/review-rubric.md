---
review: rubric-walker
target: ARCHITECTURE-SPINE.md (Companions v1, feature altitude, status: draft)
role: judges the spine against the good-spine checklist
verdict: pass-with-findings
reviewer: rubric-walker
date: 2026-07-19
---

# Rubric-Walker Review — Companions v1 Architecture Spine

> Walks the six checklist items. For each: does the spine satisfy it, the real divergences the spine FAILS to fix for the level below (epics/stories), ADs whose Rule is not enforceable or does not prevent the stated divergence, Deferred items that could still let two units diverge, and whole dimensions left silent. Verdict + findings at the end.

## Pre-walk (what the spine owns)

The spine carries 24 ADs, an Accepted-Risk Register, Consistency Conventions, a web-verified Stack, four mermaid diagrams (paradigm, modules, topology/modes, deployment envelope), a source tree, a Capability→Architecture Map, a Deferred list, and cross-artifact reconciliation items. The PRD is `status: final` and named as the binding product contract; the spine explicitly fixes only architecture-level invariants + the PRD's deferred items (OQ-4, OQ-11, OIDC flow, threat model, config/fail-fast, relay/splice core, module boundary). That altitude framing is correct and consistently applied.

---

## Checklist walk

### 1. Fixes the real divergence points for the level below — and misses none?  **MOSTLY YES, with two real gaps.**

The load-bearing divergence points an epic/story split could fracture on are all pinned:

- Threading model (the PRD-positioning-vs-reality tension) — AD-1/4/5/6 fix three coherent models, VT-control-plane-only, `StructuredTaskScope` preview-excluded. This was the headline risk; it is settled.
- Relay/splice transition — AD-2 (flip-flag, framed-`ByteBuf` not raw stream, `SmppFrameDecoder` stays active, no live `pipeline.remove()`) is concrete enough that two relay stories cannot diverge.
- PDU handling boundary — AD-3; bind/unbind-only inspection is unambiguous.
- Module boundary — AD-7 (inward-only `proxy → codec`, codec PURE); enforceable.
- State ownership — AD-8 + AD-9 (only three mutable buckets; `message_id → system_id` never exists; A-1 load-bearing with smoke-test).
- Credential model + fail-closed + mTLS chain depth + identity forwarding + legacy-leg-unauthenticated — AD-10/11/13/14/15.
- Config/fail-fast, secrets injection, metrics posture, egress TLS endpoint ID, allocator, graceful shutdown, native-image, test toolchain — AD-16..24.

**Real divergence points NOT fixed (findings F1, F2 below):**

- **F1 (medium) — The proxy→OIDC-provider transport is not pinned to TLS.** SEC-3 requires the provider link to be "authenticated AND encrypted." AD-12 fixes the ROPC grant + RFC 8705 mTLS *client credential* but never says the *base transport* to the token endpoint must be HTTPS, and AD-17's fail-fast list (line 156) rejects an "unset" provider URL but NOT an `http://` one. With the `client_secret` branch of AD-12, a story can send the legacy password + client secret in cleartext to an internal `http://` provider and still pass every AD. The Capability Map (line 305) maps SEC-1..5 to AD-3/4/13/20/24 — AD-12 is absent — so no AD actually enforces SEC-3's "encrypted" half. For a security-branded product this is the kind of small gap that lets the OIDC-adapter story and the fail-fast story assume differently.
- **F2 (low-medium) — Ingress routing cardinality (1:1 vs 1:many carriers) is doubly-deferred.** PRD §8 explicitly defers "whether a single v1 instance fronts multiple carriers" *to architecture*; the spine re-defers it to "config-schema detail" (line 317). Only the invariant ("immutable post-startup, keyed by `system_id`") is fixed. A routing-table story and a config-schema story can assume different cardinalities. The cardinality is an architecture-level invariant (it changes connection-pair state shape and metrics cardinality), not a config-key detail.

### 2. Every AD's Rule enforceable and actually prevents its stated divergence?  **YES.**

Walked all 24. Each Rule is concrete enough to be machine- or review-checkable and each lands on its stated "Prevents":

- AD-2's "no live pipeline surgery" + atomic flag flip mechanically prevents the live-mutation race.
- AD-5's "never load-bearing, never in the default build path" is the right framing for `StructuredTaskScope` preview — prevents the LTS-break via a process-wide `--enable-preview`.
- AD-7's inward-only seam is Gradle-enforceable (codec build can't resolve proxy packages).
- AD-11 enumerates the indeterminate cases (timeout/network/5xx/malformed/sig-mismatch/JWKS-refresh-failure) — each maps to a testable DENY.
- AD-12 "re-validate every bind; cache JWKS only" directly closes the verdict-cache security hole.
- AD-13 "trust store never falls back to `cacerts`; fail-fast if absent/empty; REQUIRE never WANT" directly prevents trust-root collapse.
- AD-20 "explicitly set `endpointIdentificationAlgorithm`" directly prevents the Netty 4.2 raw-IP egress break.
- AD-23 "produce no native binary" + revisit-trigger prevents the second build matrix + ZGC regression.

No AD found whose Rule fails to prevent its stated divergence. Two minor enforcement notes (not findings, recorded for the walkthrough):

- AD-1/AD-4 ("VTs never carry steady-state bytes"; "no blocking work on the event loop") are convention-enforced, not mechanically asserted. Standard for spine altitude; the brief's JFR `jdk.VirtualThreadPinned` discipline (addendum A4) is the natural mechanical backstop — worth referencing from AD-4.
- AD-13's "maxPathLength 5" parenthetical is the `PKIXBuilderParameters` default and is correct; the load-bearing clause ("rely on PKIX defaults, do not override, no custom chain-validation code") is what matters and is sound.

### 3. Anything under Deferred that could let two units diverge?  **ONE borderline (F2), rest clean.**

- Exact cipher/TLS allowlist (line 315) — operator-tunable; the TLS *floor* is pinned by AD-17's "TLS floor violated" + SEC-1 (1.2 min / 1.3 preferred). A v1 still needs a *default* allowlist that ships; without one fixed, two stories could pick different defaults (see F3).
- JWKS TTL / refresh-ahead / ROPC timeouts (line 316) — clean: AD-12 fixes cache *type* (JWKS only), only TTL is deferred.
- Routing-table format & multi-carrier semantics (line 317) — **the borderline one (F2)**: cardinality not fixed.
- Prometheus buckets / scrape handler exacts (line 318) — clean; AD-19 fixes posture.
- `application.yml` keys / Docker image layout / healthprobe (line 319) — Docker image *base/runtime* strategy is not fixed even though the Stack names jlink (see F4); healthprobe is genuinely a bootstrap-story detail.
- DLR-splice byte mechanics (line 320) — clean; determined by AD-2/AD-9.
- A-1 real-carrier test plan (line 321) — clean; non-CI ops step.
- Full STRIDE/DFD threat model (line 322) — clean for this altitude; load-bearing trust invariants are in the spine (AD-10/11/14/15/19 + the register), exhaustive enumeration belongs in the walkthrough.
- Perf-harness exacts (line 323) — clean; AD-24 fixes the toolchain.
- Native-image build (line 324) — clean; explicitly out (AD-23).
- Scaffolding for future siblings (line 325) — clean; only forward-looking invariant is the inward-only codec seam (AD-7).

### 4. Named tech verified-current?  **YES (accepted as web-verified 2026-07).**

The spine credits "web-verified current at authoring (2026-07)" and the `.memlog.md` carries the per-claim evidence trail (6-agent fact-sweep). Spot checks that matter:

- JDK 25 LTS — correct (Oracle's 2-year LTS cadence: 17/21/25).
- Netty 4.2.16.Final via `netty-bom`; 4.2 IoHandler API (`MultiThreadIoEventLoopGroup(NioIoHandler.newFactory())`); NIO/Epoll only, not io_uring (Java-25 shutdown regression); Netty 5 abandoned — all correct and internally consistent.
- Spring Boot 4.1.x on Spring Framework 7.0.8+, JDK 25 — consistent with the cited GA timeline.
- Nimbus 10.9.1 (≥10.0.2 for CVE-2025-53864); jSMPP `org.jsmpp:jsmpp:3.0.2` (not the GitHub-misleading 2.3.11); Keycloak 26.x reference; generational ZGC as the only ZGC mode in JDK 25 (legacy `-ZGenerational` removed) — all correct.
- GraalVM for JDK 25 (Oracle 25.1.3 / CE 25.0.2), correctly scoped to stretch-only.

No stale or hallucinated version in the load-bearing set. The pin-build-25.0.x hedge (so "latest 25" can't silently advance preview semantics) is exactly the right call.

### 5. If a spec drove it, covers that spec's capabilities?  **YES, with one traceability gap (F5).**

Walked every PRD FR/NFR group against the Capability→Architecture Map and the binds list:

- FR-TRANSIT/SEC/AUTH/DEPLOY/OBS, PERF, SEC, REL, COMP, MAINT, DEP, OPS, OBS — all bound (frontmatter lines 12-23) and all mapped to at least one owning AD. OQ-4→AD-13, OQ-11→AD-23, OIDC→AD-12, config→AD-16/17 — every PRD-deferred item landed as an AD.
- **F5 (low) — PRIV-1 is absent from the `binds:` list and has no owning AD.** The spine binds 13 requirement groups but omits PRIV-1 ("Do not persist SMS message bodies; `system_id` may be logged"). The capability is *implicitly* covered (AD-3 opaque-splice, AD-19 content-never-emitted, AD-8 no message-state) but the "no persistence" guarantee is never stated as an invariant and the binds-list traceability is broken. For a security-branded product the privacy NFR should be explicitly bound and owned. This is a traceability/altitude-coverage defect, not a missing capability.

No PRD capability is left without an AD mapping other than PRIV-1.

### 6. Every dimension the altitude owns decided / deferred / OQ — no whole silent dimension?  **YES.**

The three dimensions the checklist singles out:

- **Deployment & environments** — present as a named section "Deployment & environments (operational envelope)" with a diagram: single instance, Linux x86/ARM, IPv4, JDK 25, ZGC, JAR + Docker, mounted file-path secrets, external OIDC provider, loopback `/metrics`. Single-instance/no-HA, deploy-time cert provisioning, no runtime ACME/SPIFFE, Mode C rotation = re-deploy all stated. Not silent. (One sub-detail unfixed — F4: Docker base/runtime strategy.)
- **Infra/provider strategy** — BYO operator OIDC provider (Keycloak reference), BYO PKI/trust store, SMSC external and sole credential authority. Explicitly "no bundled authority provider, no cert issuance." Not silent.
- **Operations** — covered across AD-17 (startup validation/fail-fast), AD-19 (logging + `/metrics` posture, no management API), AD-22 (graceful shutdown sequence), AD-23 (no second build matrix), AD-24 (test/conformance toolchain), the Accepted-Risk Register (cert rotation, provider outage, single-instance), and Deferred (healthprobe design). Not silent.

Other dimensions the altitude owns — security/trust, performance/capacity, data/formats, error handling, concurrency, observability — are all decided or explicitly deferred. No whole dimension left silent.

---

## Findings (most-severe first)

| # | Severity | AD / location | Summary | Suggested fix |
|---|---|---|---|---|
| F1 | medium | AD-12 / AD-17 (line 156, 305) | The proxy→OIDC-provider *transport* is not pinned to TLS. SEC-3 requires the provider link be authenticated AND encrypted; AD-12 fixes only the ROPC client credential, and AD-17 fail-fasts on an "unset" provider URL but not an `http://` one. The `client_secret` branch can send the legacy password in cleartext. Capability Map omits AD-12 from the SEC-1..5 row. | Add to AD-17's fail-fast list: "OIDC provider URL scheme not `https`" (fail-fast refuse). Add to AD-12: "the provider token/JWKS endpoints are reached over TLS (HTTPS); never HTTP." Add AD-12 to the SEC-1..5 row of the Capability Map. |
| F2 | low-medium | Deferred line 317 / AD-8 | Ingress routing cardinality (single-carrier 1:1 vs multi-carrier 1:many) is doubly-deferred — PRD §8 defers it to architecture; the spine re-defers it to "config-schema detail." It changes connection-pair state shape and metrics cardinality, so it is an architecture-level invariant, not a config-key detail. | Decide at the spine: state whether a v1 ingress instance fronts exactly one carrier egress or N. If N, fix the upper bound and the `system_id → egress-target` resolution rule. Leave only the *format* (YAML shape) deferred. |
| F3 | low | Deferred line 315 / SEC-1 | No default TLS cipher/protocol allowlist is fixed. SEC-1 requires the product "publish a cipher allowlist policy"; the floor (1.2 min, 1.3 preferred) is pinned by AD-17, but a v1 must ship a concrete default allowlist or two stories pick different defaults. | Either fix a shipped default allowlist in the spine (one line: "default = TLS 1.3 suites + these 1.2 AEAD suites; operator-tunable"), or name a single owning story in the Deferred entry so no two stories assume the default. |
| F4 | low | Stack line 235 / AD-23 / Deferred line 319 | Docker image base/runtime strategy is not fixed. Stack names "jlink ~45-66 MB"; AD-23 says "runnable JAR + Docker"; Deferred defers "Docker image layout." Whether the image is `distroless + jlink`, a JRE base, or a full JDK base is undecided — two packaging stories could diverge, and it affects the cold-start/footprint claims. | Pin the Docker base strategy (e.g., "distroless + jlink runtime image, JDK 25 modules") at the spine, or name a single owning story. This is an operational-envelope detail the spine already gestures at. |
| F5 | low | frontmatter binds (lines 11-23) | PRIV-1 is absent from the `binds:` list and has no owning AD. The privacy guarantee ("never persist message bodies; `system_id` may be logged") is only implicit in AD-3/8/19 and is never stated as an invariant. | Add `PRIV-1` to the `binds:` list and either add a short "no persistence of message bodies or passwords" clause to an existing AD (AD-3 or AD-8) or a one-line Consistency Convention row. |
| F6 | low | Consistency Conventions (line 218) | The `bind_resp` status-code mapping for each OIDC/fail-closed outcome is not fixed. The convention says rejections "carry a SMPP `bind_resp` status code" but does not say which. Two bind-adjudication stories could emit `ESME_R_INVSYSID` vs `ESME_R_AUTHERR` vs `ESME_R_SYSERR` for the same OIDC 401/timeout. | Either fix the mapping at the spine (a small table: OIDC 401 → `ESME_R_INVSYSID`; indeterminate/timeout → `ESME_R_SYSERR`; etc.) or name a single owning story. Low blast radius (wire-visible only), but cheap to fix now. |

### Notes (not findings — for the walkthrough artifact, not the spine)

- **A-1 contingency is binary.** AD-9 owns the load-bearing assumption and AD-24 owns the smoke-test, but the spine's fallback ("if A-1 is false the design must become stateful") implies a spine rewrite mid-build with no partial design to fall back to. Inherent to a genuinely load-bearing assumption; flag explicitly in the walkthrough's risk section so a story author doesn't discover it late.
- **AD-1/AD-4 mechanical enforcement.** "VTs never carry steady-state bytes" and "no blocking work on the event loop" are convention-enforced. Consider a one-line cross-reference from AD-4 to the JFR `jdk.VirtualThreadPinned` discipline (brief addendum A4) as the mechanical backstop. Not a spine defect.

---

## Verdict: **pass-with-findings**

The spine fixes the real divergence points for the level below (epics/stories). Every AD's Rule is enforceable and actually prevents its stated divergence. The stack is verified-current. Every PRD-deferred item (OQ-4, OQ-11, OIDC flow, threat model, config/fail-fast) landed as an AD. No whole dimension — including deployment/environments, infra/provider strategy, and operations — is left silent. The cross-artifact reconciliation items (the "virtual-thread relay" wording, Spring Boot stack naming) are correctly flagged for finalize rather than silently absorbed.

Six findings survive verification, one medium (F1: OIDC-provider transport not pinned to TLS — a real SEC-3 coverage gap), one low-medium (F2: routing cardinality doubly-deferred), and four low (F3 default cipher allowlist, F4 Docker base/runtime, F5 PRIV-1 not bound, F6 bind_resp status mapping). None blocks the spine from being walked down to epics/stories; F1 and F2 should be closed before the OIDC-adapter / routing stories are authored so those stories cannot diverge. The rest can be fixed at finalize or owned by a single named story.

Recommended finalize actions: close F1 + F2 in the spine; close F5 in the binds list; assign single owning stories for F3, F4, F6.
