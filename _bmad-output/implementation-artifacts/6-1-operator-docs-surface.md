---
title: 'Story 6.1 — the operator docs surface: config reference, per-mode deployment guide, runbooks, cipher policy (AD-31/OPS-1)'
type: 'feature'
created: '2026-09-12'
status: 'in-progress'
route: 'dispatch'
baseline_commit: e30862d2a92996e82650a87432d571c672b73286
review_loop_iteration: 0
context:
  - {project-root}/_bmad-output/implementation-artifacts/epic-6-context.md
  - {project-root}/_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md
  - {project-root}/_bmad-output/implementation-artifacts/deferred-work.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The proxy is headless — "documentation is the operator surface" (OPS-1, prd.md §7.8): no UI, no management API, no dashboard. But `docs/` today holds exactly two pages (the JVM-flag contract, the A-1 carrier plan) — the AD-31-mandated surface (config reference, per-mode A/B/C deployment guide, runbooks, cipher-allowlist policy) does not exist. An operator cannot go zero → running from the repo: the canonical `docker run` invocation (mounts, perms, published port, exit semantics) lives only in test code (BH15); the ROPC removal-track disclosure (OBS-033) and Mode B warning text (OBS-031) are catalog rows, not pages; the deny-surface debugging knowledge (where each failure surfaces — wire vs. log vs. metric) is scattered across story files and the spine.

**Approach:** Author the complete AD-31 surface under `docs/`, every claim sourced from AS-BUILT code and config (the `application.yml` + config records are the oracle — the spine deliberately deferred exact key names): (1) a config reference documenting every `companion.*` key — common keys with defaults, all five role×mode branches, the AD-17 required/optional/forbidden matrix, file-path secrets per AD-18, and the retired keys that now refuse startup; (2) a per-mode deployment guide covering forward A/C and reverse A/B/C in both packaged shapes — the JAR launch via the flag-contract page and the canonical `docker run` recipe (the BH15 seed), the ROPC/Direct-Access-Grants removal-track warning + Keycloak ≥26.7.0 pin + DAG-enablement prerequisite (OBS-033), the Mode B plaintext warning text + opt-in ack (OBS-031), the BH6 base-image digest-pin policy decision, and honest e2e-evidence pointers (DEPLOY-005/009/015 scope; the mode A/C + auth-DENY journey-widening decision stays 6.2's); (3) runbooks for the deny surface and debugging — AD-32 case-4 verbatim forward vs. AD-33 collapsed deny, the `OPERATOR_WARNING`/`OPAQUE_TOKEN_WARNING` banners, the JSON log-event and `/metrics` references, shutdown/exit semantics, Mode A ACL isolation (SEC-065/OBS-034), JFR/dump hygiene (SEC-049); (4) the cipher-allowlist policy page (OBS-032, unblocked by AD-34); plus a refresh (not re-author) of `docs/a-1-carrier-test-plan.md`. Catalog close-out is dated markers only — the OBS docs-scan techniques are retired per the owner's 2026-09-10 no-Java-over-`*.md` rule; page coherence is a review-time duty.

## Boundaries & Constraints

**Always:**
- Every page's claims are sourced from as-built reality and cite it (file paths, exact key/metric/event names pulled from `application.yml`, the config records, the observability classes — never from the spine's pre-implementation wording). Voice and density match `docs/operator-jvm-flag-contract.md`: dated owner decisions, honest scope statements, zero marketing.
- The deployment guide carries the three 5.2-closure defers exactly as epic-6-context routes them: the BH15 `docker run` recipe AUTHORED here; the journey-widening EVIDENCE POINTER here (the widening decision itself is 6.2's); the BH7 DockerRig note as a pointer to 6.2's consolidation.
- The ROPC disclosure is the OBS-033 three-parter, verbatim in substance: (a) v1 authenticates via ROPC / Direct Access Grants; (b) RFC 9700 / OAuth 2.1 removal-track status; (c) operators must pin their Keycloak build (≥26.7.0, re-validate each minor — the AD-12 accepted-risk register's pinned verdict, not fresh research). Plus the DAG prerequisite: per-client, OFF since Keycloak 26.2, enable it or every bind denies fail-closed at first bind with the starred `OPERATOR_WARNING`.
- The Mode B section documents the SHIPPED banner (quote `CompanionModeBWarning` verbatim), the `companion.reverse.mode-b.acknowledged=true` opt-in, and the accepted-risk stance — and the guide documents Mode A's `CompanionModeAWarning` analog.
- `docs/a-1-carrier-test-plan.md` is refreshed in place: every claim re-checked against as-built (flags, ports, metric names, log events), the OBS-035/036/037 falsifiable shape intact — the legacy `A1CarrierPlanDocsTest` pins substrings and must stay GREEN.
- Close-out discipline: catalog rows close with DATED markers (OBS-029..034, SEC-065, SEC-049 as OWNER-AMENDED — scan technique retired per the 2026-09-10 rule, deliverable = the page; OBS-035/036/037 note the refresh); deferred-work BH6/BH15 marked resolved-here; `epic-6-context.md` regenerated to as-built.
- `./gradlew clean build --console=plain` stays GREEN and untouched — this is a docs-only story (zero main-source, test, or Gradle changes).

**Never:**
- No Java/test parses any new page (owner rule 2026-09-10: no Java tests whose oracle is a markdown page; `A1CarrierPlanDocsTest` is legacy, not a pattern to copy) — page↔reality coherence is enforced by this story's review sweep, not by code.
- No perf numbers, no perf-report page, no JMH bands (Epic 7's 7.1 authors those under PERF-070/071); the runbooks' tuning sections link forward to where numbers WILL publish without stating any.
- No sandbox content (6.3's README), no conformance execution or DockerRig consolidation (6.2), no new config keys, no code changes of any kind, no CI wiring (none exists, owner 2026-09-11).
- No re-authoring of `docs/operator-jvm-flag-contract.md` — cross-link it as the flag authority; a factual drift found against as-built is a dated amendment, not a rewrite.
- No secrets values, no real hostnames/credentials in examples — file paths only (AD-18), placeholder domains.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Operator zero→running (JAR) | Follows the deployment guide's reverse.mode-b walkthrough from a clean checkout | `./gradlew :proxy:bootJar`, flag-contract launch, secret files by path → `startup_summary` JSON line + Mode B WARN line; the guide names both expected observations | Any command that fails as written = guide bug → fixed in-story, never footnoted |
| Operator zero→running (Docker) | Follows the `docker run` recipe (BH15) | World-readable-or-65532-owned `/run/secrets` mounts, published SMPP port ONLY (no `-p 9090` — metrics is loopback-only, in-container via `docker exec` java), no-args → AD-17 refusal quoted, `docker stop` → exit 143 | Wrong perms/paths in the recipe reproduce the SEC-060 refusal text the guide must document, not hide |
| Config-reference lookup | Operator searches any live `companion.*` key | Documented: type, default, unit, fail-fast guard, which cells require it — sourced from `application.yml` + the records | A key on the page absent from code (or vice versa) = drift → the T4 sweep fails the story |
| Retired-key trap | Operator's old config carries `oidc.jwks-cache-ttl` / `bind.max-connections` / `tls.contexts` / mTLS-keystore arm | The config reference documents each retirement + the loud `ignoreUnknownFields=false` refusal the stale config now gets | Documenting a retired key as if live = the R37 docs-mislead failure mode |
| Bind denied — operator debugs | Runbook's deny-surface table | SMSC-originated non-ROK → verbatim on the wire (AD-32 case 4); proxy-originated deny → ONE generic code on the wire (AD-33), rich verdict in `bind_reject` log line + `relay_binds_rejected_total` only | A runbook row that cannot name WHERE the outcome surfaces is not shipped |
| Misconfigured IdP | Dead/wrong ROPC provider under sustained binds | Runbook documents the once-per-condition starred `OPERATOR_WARNING` + `OPERATOR_WARNING_REPEAT` one-liners + the DAG remediation | — |
| Cipher drift question | Operator compares the policy page vs. their runtime | Page lists AD-34's exact defaults = the shipped `application.yml` values; documents per-context empty-intersection fail-fast and how to tune | Page/yml mismatch = drift → T4 sweep fails |
| A-1 plan refresh | `clean build` after the refresh | `A1CarrierPlanDocsTest` GREEN — pinned falsifiable substrings (≥2 concurrent binds, same system_id, ROK, DLR-on-bind-A) survive verbatim | Breaking the legacy gate while "refreshing" = refresh overreach → revert the wording |

**Decisions (owner, 2026-09-12, to ratify or amend at dispatch):**
- `docs/` layout: four new pages — `configuration.md`, `deployment-guide.md`, `runbooks.md`, `cipher-allowlist-policy.md` — beside the existing `operator-jvm-flag-contract.md` (flag authority, cross-linked never duplicated) and refreshed `a-1-carrier-test-plan.md`. A one-screen `docs/README.md` index is optional at dispatch (default: yes, six pages warrant a landing point).
- BH6 base-image digest-pin policy: default arm = DOCUMENT the current mutable-tag (`base-debian12:nonroot`) posture + the drift tradeoff (CVE-freshness vs. rebuild reproducibility) in the deployment guide's Docker section, with the release/publish-tooling stance (owner 2026-09-11) named as the future home of any digest pin. The alternative (pin a digest now) is an owner amendment at dispatch.
- The runbooks' evidence base is the 4.1/5.1/5.2 test record (log events, metric names, exit semantics as pinned by `PackagedBootSmokeTest`/`DockerImageBootSmokeTest`/`DockerSecretsE2eTest`) — the sandbox (6.3) may later earn a dated addendum; none is pre-authored.

</frozen-after-approval>

## Code Map

- `proxy/src/main/resources/application.yml` -- the ORACLE for the config reference: every live `companion.*` key, the five branches, defaults, and the dated policy blocks (JWT-only, DAG prerequisite, derived token endpoint). The page documents what this file ships, key for key.
- `proxy/src/main/java/smpp/companion/proxy/config/` -- `CompanionProperties` + the record tree + `CompanionConfigValidator`: types, compact-ctor guards, the AD-17 matrix enforcement, `budget-check` policy — the fail-fast behaviors the config reference documents per key.
- `docs/operator-jvm-flag-contract.md` -- the precedent for voice/density AND the flag authority the deployment guide cross-links (the four flags, floor+mirror rule, lazy-init deviation). Amended only if a factual drift is found.
- `proxy/src/main/java/smpp/companion/proxy/observability/` (`StartupSummaryLogger`, `MeteredRelayObserver`, `ResourceMetrics`, `ObservabilityConfig`) -- the exact JSON event names/fields (`startup_summary`, `bind_accept`, `bind_reject` + `verdict`/`bind_resp_command_status`) and metric names/labels (`relay_pdus_total`, `relay_binds_accepted_total{system_id}`, `relay_binds_rejected_total`, `relay_binds_unknown_total`, `relay_connections_closed_total{direction,reason}`, `relay_direct_memory_used`, `ropc_adjudications_active` + the JVM binder families) the runbook references.
- `proxy/src/main/java/smpp/companion/proxy/config/CompanionModeBWarning.java` + `CompanionModeAWarning.java` -- the shipped banner text the deployment guide quotes verbatim (WARN-level JSON lines since 5.1 T3).
- `proxy/src/main/java/smpp/companion/proxy/security/RopcBindCredentialVerifier.java` -- the `OPERATOR_WARNING` (once-per-condition starred, provider-status-keyed) + `OPAQUE_TOKEN_WARNING` semantics the runbook documents.
- `proxy/src/docker/Dockerfile` + `buildSrc/src/main/kotlin/smpp/deploy/` (`DockerImageTask.kt`, `AssembleDockerContextTask.kt`) -- the Docker shape facts: distroless `base-debian12:nonroot` (the BH6 line), exec-form ENTRYPOINT, `USER nonroot:nonroot`, `:proxy:dockerImage` deliberately outside `build`/`check`.
- `proxy/src/test/java/smpp/companion/proxy/bootstrap/PackagedBootSmokeTest.java` + `proxy/src/test/java/.../docker/` (`DockerImageBootSmokeTest`, `DockerSecretsE2eTest`) -- the launch recipes the guide mirrors BY HAND (mounts, perms, published port, expected observations, exit semantics) — the BH15 source of truth.
- `proxy/src/test/java/smpp/companion/proxy/relay/A1CarrierPlanDocsTest.java` -- the LEGACY docs gate pinning the A-1 plan's falsifiable substrings; must stay GREEN through the refresh; NOT a pattern for new tests.
- `docs/a-1-carrier-test-plan.md` -- refreshed in place (OBS-035/036/037 shape intact).
- `_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md` -- AD-17 matrix, AD-18, AD-31, AD-32/33 wire contracts, AD-34 cipher defaults, AD-30 formula, the Accepted-Risk Register (ROPC/Mode B/preview-STS entries the docs mirror).
- `_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md` -- the rows this story closes: OBS-029..034 (docs pages), SEC-065/049 (runbook content), OBS-035..037 (refresh note), DEPLOY-005/009/015 (the evidence the guide points at); PERF-070/071 boundary (Epic 7's).
- `_bmad-output/implementation-artifacts/deferred-work.md` -- the 5.2 close-out section: the three defers this story routes + BH6; markers updated at T4.

## Tasks & Acceptance

**Execution:**
- [x] **T1 — the config reference (`docs/configuration.md`)** — Every live `companion.*` key from `application.yml` + the config records: common keys (`bind.port/host/adjudication-deadline/pre-couple-idle-timeout`, `memory.max-inbound-depth/concurrent-pairs/safety-factor/budget-check`, `tls.protocols/tls12-cipher-suites/tls13-cipher-suites`, `metrics.port`, `shutdown.drain-timeout`) with type/default/guard; the five branches (forward.mode-a/mode-c + tls-contexts, reverse.mode-a/mode-b/mode-c) with the AD-17 required/optional/forbidden matrix; secrets as file paths (AD-18); the derived-token-endpoint + DAG policy blocks; the RETIRED keys and their loud refusals; cross-links to the flag-contract page (`MaxDirectMemorySize` interlock). Mutation: the page↔yml↔records sweep — any key documented-but-absent, absent-but-live, or default-mismatched fails the story. (AC: 1)
- [ ] **T2 — the per-mode deployment guide (`docs/deployment-guide.md`)** — Per-cell walkthroughs (forward A/C: trust store + routing + per-instance/per-target certs; reverse A/B/C: server cert, REQUIRE trust store, OIDC, SMSC endpoint, Mode B ack) × both shapes: the JAR launch (flag-contract link, arg shape from `TestCompanionConfigs`-style examples) and the canonical `docker run` recipe (BH15: `/run/secrets` mounts + perms guidance, published SMPP port only, no-args → the quoted AD-17 refusal, `docker stop` → 143, no `--memory` cap below the AD-30 budget); the OBS-033 ROPC three-parter + DAG-enablement prerequisite; the Mode A/B banner texts quoted + opt-in semantics; the BH6 policy decision (per the ratified arm); honest evidence pointers (DEPLOY-005/015 reverse-B allow-path scope + DEPLOY-009 refusals; mode A/C + auth-DENY widening = 6.2's decision, DockerRig consolidation = 6.2's BH7). Mutation: the zero→running walkthrough — both shapes executed from the page's own text on the dev box; any command/expected-observation that does not hold as written fails the story. (AC: 2, 3)
- [ ] **T3 — the runbooks + cipher policy (`docs/runbooks.md`, `docs/cipher-allowlist-policy.md`)** — Runbooks: the deny-surface table (AD-32 case-4 verbatim vs. AD-33 collapse — WHERE each surfaces: wire/log/metric); `OPERATOR_WARNING`/`OPAQUE_TOKEN_WARNING` diagnosis + DAG remediation; the JSON log-event reference (events, fields, TRACE-gated PDU bodies, password-never-logged); the `/metrics` reference (every metric + labels, loopback-only binding, Docker in-container `docker exec` access, scrape idempotence); shutdown/exit semantics (AD-22 walk order, drain-timeout, exit codes); Mode A two-proxy ACL isolation + never-cacerts default with the public-PKI opt-in (SEC-065/OBS-034); JFR/dump hygiene under the password-redaction posture (SEC-049); a troubleshooting entry table. Cipher page: AD-34 defaults verbatim from `application.yml`, per-context empty-intersection fail-fast, operator-tunability + the tuning guardrails. Mutation: every runbook row names its surface (wire/log/metric) or is cut; the cipher lists match yml byte-for-byte. (AC: 4, 5)
- [ ] **T4 — A-1 refresh, proofs, catalog, ledger** — Refresh `docs/a-1-carrier-test-plan.md` against as-built with `A1CarrierPlanDocsTest` GREEN; `./gradlew clean build --console=plain` GREEN with zero diffs outside `docs/` + planning artifacts (the docs-only claim verified by `git status`, not assumed); catalog dated markers (OBS-029..034, SEC-065, SEC-049 OWNER-AMENDED — technique retired per the 2026-09-10 rule, deliverable = page + review sweep; OBS-035..037 refresh note); deferred-work: BH6 + BH15 resolved-here markers, journey-widening + BH7 pointers visibly re-homed to 6.2; `epic-6-context.md` regenerated to as-built; optional `docs/README.md` index per the dispatch decision. Mutation: `git diff --stat` naming any file outside the allowed set = the docs-only claim false → task not complete. (AC: 6, 7, 8)

**Acceptance Criteria:**
- Given the as-built `application.yml` and config records, when the config reference is read, then every live `companion.*` key is documented with type, default, and fail-fast behavior, no retired key appears as live, and the AD-17 role×mode matrix (required/optional/forbidden per cell, forward×B structurally forbidden) is stated.
- Given a clean checkout and Docker, when an operator follows the deployment guide's reverse.mode-b walkthrough in EITHER shape, then the instance reaches `startup_summary` (and the Mode B WARN line) using only commands and expected observations the page itself provides — including the canonical `docker run` recipe with `/run/secrets` mounts, the published SMPP port only, and `docker stop` → exit 143.
- Given the deployment guide's trust section, then it discloses (a) v1 authenticates via ROPC / Direct Access Grants, (b) the RFC 9700 / OAuth 2.1 removal-track status, (c) the Keycloak build-pinning requirement (≥26.7.0, re-validate each minor), and (d) the DAG per-client enablement prerequisite with its first-bind deny consequence — and records the BH6 digest-pin policy decision with its date and owner.
- Given a denied bind, when the runbook is consulted, then it correctly names where each deny flavor surfaces — SMSC-originated non-ROK verbatim on the wire (AD-32 case 4) vs. proxy-originated single generic code (AD-33) with the rich verdict only in `bind_reject` logs and `relay_binds_rejected_total` — and the runbooks cover Mode A ACL isolation and JFR/dump hygiene.
- Given the cipher policy page, then its protocol and cipher lists match the shipped `application.yml` values exactly, and it documents the per-context empty-intersection startup refusal and the operator-tuning envelope.
- Given the refreshed A-1 carrier plan, when `./gradlew clean build --console=plain` runs, then the build is GREEN including `A1CarrierPlanDocsTest`, with every A-1 claim matching as-built reality.
- Given the story's full diff, when reviewed, then it touches only `docs/`, the story file, the catalog, the ledger, and `epic-6-context.md` — zero main-source, test, or Gradle changes; no new Java parses any `docs/` page.
- Given the catalog and ledger, when close-out markers are read, then OBS-029..034/SEC-065/SEC-049 carry dated OWNER-AMENDED markers naming the page that satisfies them, and BH6/BH15 are resolved with the journey-widening and BH7 pointers visibly re-homed to 6.2.

## Implementation Notes

## Spec Change Log

## Review Triage Log

## Design Notes

- The oracle discipline is the story's spine: `application.yml` + the config records + the observability classes are what the pages document — the spine's pre-implementation key names were deliberately deferred to the config package and are NOT authoritative. Where spine and code disagree, the page follows code and (if load-bearing) a dated spine-amendment note rides with the story.
- Voice precedent = `operator-jvm-flag-contract.md`: every page opens with status/audience/scope, carries dated owner decisions inline, and states scope honestly (what is NOT covered: perf numbers → Epic 7's page; sandbox rig → 6.3's README; conformance runs → 6.2).
- The no-Java-over-`*.md` rule inverts the catalog's original OBS-029..034 technique: those rows were authored before the 2026-09-10 owner rule. The close-out vocabulary already has the verb (`OWNER-AMENDED`, cf. DEPLOY-003's "nothing parses the page" marker) — use it, and name the review sweep as the enforcement mechanism, exactly as the flag-contract page does.
- Cross-link, never duplicate: the flag-contract page owns the JVM flag set; the config reference owns `companion.*`; the deployment guide owns per-cell recipes and links both; the runbooks own the operational surfaces. One fact, one home, every other page links to it — the drift-prevention posture that keeps six pages coherent without parsers.
- The BH15 recipe is authored from the test rigs' proven invocations (`DockerSecretsE2eTest.launchReverseBCell`) but written as OPERATOR commands — no Testcontainers, no Java — and must be executed by hand from the page at least once (T2's mutation) so the page is proven, not transcribed.
- One-task-per-conversational-step, one commit per task (repo rule). T1–T3 are each a self-contained page set; T4 is the proofs/close-out commit.

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN (includes the legacy `A1CarrierPlanDocsTest` over the refreshed A-1 plan).
- `git diff --stat <baseline>..HEAD` -- expected: only `docs/*`, `6-1-operator-docs-surface.md`, `test-coverage-scenarios.md`, `deferred-work.md`, `epic-6-context.md` (the docs-only claim, verified not assumed).

**Manual checks (the load-bearing half for a docs story):**
- Execute the deployment guide's reverse.mode-b walkthrough in both shapes from the page text alone — every command and expected observation holds.
- The page↔reality sweep: every key/metric/event/banner/cipher literal on the new pages greps back to `application.yml` / the named class; the A-1 plan's claims ditto.

## Dev Agent Record

### Agent Model Used

glm-5.2[1m] via Claude Code, 2026-09-12 — T1 execution (`docs/configuration.md`: every live `companion.*` key from `application.yml` + the config records, the AD-17 six-cell matrix, the four dated OIDC policy blocks, the retired-key table with retirement dates verified from git history, the flag-contract cross-link with the MaxDirectMemorySize interlock).

### Debug Log References

### Completion Notes List

- **T1 (2026-09-12):** the page's oracle was `application.yml` + `ProxyCompanionProperties`/`CompanionConfigValidator`/`MemoryBudget` read in full, plus the spine ADs (12/13/17/18/26/29/30/34) and `operator-jvm-flag-contract.md` for voice/interlock. The T1 mutation (page↔yml↔records sweep) was executed mechanically: every documented cipher-suite literal greps 1:1 against `application.yml`; every default literal (`2775`, `0.0.0.0`, `4s`, `30s`, `64`, `1024`, `1.5`, `fail`, `9090`, `10s`, and the 6,442,450,944 derivation) confirmed present in the oracles; every quoted refusal fragment confirmed against the record/validator/`DirectMemoryBudgetException` source; the reverse sweep (every record component → a page row) done by component enumeration. Retired-key dates verified via `git log -S` (`companion.role` → c4afa17 2026-08-04; `bind.max-connections` + top-level `tls.contexts` → the 3.3 checkpoint rework note in 35fd64d, 2026-08-26; `client-mtls-keystore`/`client-credential-path` → 5f5dd9b pre-release; `jwks-cache-ttl` → de6a806 2026-08-27). Two content decisions beyond the spec letter, both sourced: the `companion.tls.*` policy-scope list INCLUDES the reverse's IdP client context (`IdpSslContextFactory` consumes `properties.tls()` and refuses on empty intersection — verified in source); the supply-channel list includes Java system properties (between args and env in Spring Boot precedence) with a pointer that pre-`-jar` position is flag-contract territory. Banner texts are cross-linked to T2's deployment guide (their verbatim home), not duplicated. Links to `deployment-guide.md`/`runbooks.md`/`cipher-allowlist-policy.md` are forward links to this story's T2/T3 pages.

### File List

- `docs/configuration.md` — created (T1).

