# Epic 6 Context: Correct and document the proxy — the Kannel sandbox, composed conformance, and the operator docs surface

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->
<!-- Compiled 2026-09-12 (the Epic 6/7 split, owner direction same date): the former Epic 6's performance half
     moved to Epic 7 ("epic 7 focuses on performance measurement"); THIS epic keeps "having the proxy documented
     and corrected" plus the owner-directed Kannel docker-compose sandbox for debugging and correctness proof
     (example: /home/ildar/Documents/smpp-sandbox, the repo's pre-project origin playground, whose README plan
     item 3 is literally this proxy). The three 5.2-closure defers re-homed here stay here (journey-widening,
     DockerRig consolidation, docker-run recipe). Same-date execution order set: docs → conformance → sandbox
     (the sandbox story, created first as 6.1, renumbered to 6.3 — see Stories). -->
<!-- Regenerated to as-built 2026-09-13 (Story 6.1 T4; review closed same date): 6.1 is DONE — the AD-31 surface exists under docs/
     (README.md indexes configuration.md, deployment-guide.md, runbooks.md, cipher-allowlist-policy.md beside
     the flag-contract page; a-1-carrier-test-plan.md refreshed in place); the 5.2 defers it carried are
     ledgered (BH15 authored + BH6 documented = resolved; journey-widening + BH7 visibly re-homed to 6.2). -->
<!-- Regenerated to as-built 2026-09-16 (Story 6.2 T4): 6.2's four tasks landed — T1 the DockerRig fold
     (BH7 RESOLVED: testsupport/DockerRig.java, both 5.2 suites re-pointed byte-identical), T2 the E2E-001
     in-JVM composed suite (ComposedChainE2eTest — the row's "two in-JVM proxy instances" letter; the real
     ROPC verifier over the TLS stand-in, closing the 3.3 ROPC-through-TLS gap), T3 the packaged rung
     (ComposedPackagedE2eTest + ComposedDockerE2eTest through the folded rig — the spine's AD-24/DEP-1
     letter) with the journey-widening decision EXECUTED per the ratified default (mode C composed +
     auth-DENY in both shapes; mode A stays with the loopback suite + the DEPLOY-005 structural-sameness
     argument), T4 the close-out (deployment guide machine-proven matrix trued + the conformance-run
     section added and executed from the page; docs/README trued; catalog markers E2E-001 LANDED +
     DEPLOY-005 amended, count stays 254; ledger resolutions BH7 / journey-widening / ROPC-through-TLS).
     Zero main-source and zero Gradle/buildSrc changes by contract; COMP-1's independent-stack point and
     REL-3's composed drain (SIGTERM/docker stop → 143, both shapes) are stated on the markers. -->
<!-- Flipped done 2026-09-16 (review round 1 closed same date, fixes at 3bc56f2): 10 review fixes
     applied + 2 owner ratifications (the REL-3 forward-first drain asymmetry — E2E-001 marker
     point 7; the assertRokBindResp one-prose unification), 2 defers to the ledger (a standing
     one-DockerRig structural guard; the daemon-less observation), 9 findings rejected with
     evidence (jSMPP 3.0.2's 60s enquireLinkTimer default bytecode-verified twice). 16 targeted
     rows re-verified green, both Docker suites included. -->
<!-- Regenerated to as-built 2026-09-17 (Story 6.3 T4): 6.3's four tasks landed — T1 the rig in-repo
     (`sandbox/`: the ported 7-service compose chain, byte-identical except the ONE wiring re-point
     14567→2775 + the pinned-source Kannel 1.5.0 Dockerfile + conf/init.sql + healthchecks + the
     bring-up guide and its RU twin; the live conf-refusal mutation run), T2 the compose Keycloak
     (26.7.0, fixture-mirrored realm, DAG-on confidential client whose secret is GENERATED at import
     and fetched by path — AD-18) + the host-run packaged-jar launch recipe (§5, executed verbatim:
     Mode B banner, startup_summary, bind_accept coupled through the proxy; the live wrong-egress-port
     and deny-arm mutations), T3 the four correctness journeys with per-hop expected observations +
     the debugging guide (§6/§7, all executed live; the rig's one conf fix = the smsbox-route
     MO-routing delta the deliver_sm journey required), T4 the close-out (the Gradle-inert
     `./gradlew clean build --console=plain` verified GREEN — 521 tests, 0 failed, 0 skipped, zero
     Gradle-file changes; the journeys landed as catalog rows E2E-002..005, manual-rig ops-tier per
     the OBS-035/037 precedent; the Kannel quirks stay README interop notes — neither actionable, so
     no deferred-work entry; this file regenerated). Nothing bounced: no proxy defect surfaced via
     Kannel. -->
<!-- Amended 2026-09-18 (Story 6.3 T5, the owner-added task — dated addendum, not a regeneration):
     the three docker-packaged combo runbooks landed under sandbox/runbooks/ (reverse.mode-b;
     forward+reverse mode A; forward+reverse mode C — EN + RU twins, indexed by README §5.6 in
     both languages), every proxy instance the Epic-5 distroless image on network_mode: host with
     the host-built jar bind-mounted over the image's copy (rebuild + docker restart = jar swap,
     no image rebuild). Each runbook was followed verbatim to bind_accept coupled on the live rig
     2026-09-18: sends byte-intact through both composed chains, the mTLS REQUIRE-gate three-way
     probe (no-cert dials never reach SMPP), the composed reverse-down mutation on both pairs,
     and the jar-swap restart cycle. The ONE new material is sandbox/certs/ — the SMPP-leg
     fixture PKI, cmp-verified copies of the committed test resources (the T2 keycloak/certs/
     precedent). Zero Gradle, build-file, or main-source changes; nothing committed by the agent.
     T5's runs are dated into the test catalog (E2E-002..005's families, manual rig, non-CI ops
     tier); the §6.4 D1 deny journey stays single-proxy by design (an off-table system_id is
     denied at the forward's routing table — the runbooks' routing-miss rows state the shape). -->
<!-- Flipped done 2026-09-19: review round 1 closed 2026-09-18 (7cb0d8f — doc-consistency fixes +
     ledger truing; the story file's status rode with it), then T6, the owner-added operator-first
     docs task, landed 2026-09-19 (3e38797) — the root project README (EN + RU), the three runbooks
     restructured with every command and live-observed value preserved verbatim, the README
     orientation tables, and the owner terminology sweep (use case = role + mode; connect for wire
     interactions; coupling for app/memory; measurement is within Epic 7's scope); clean build
     re-verified GREEN (3m 7s). Epic-6 done with it — all three stories closed; the epic-6
     retrospective stays optional. -->

## Goal

Make the proxy CORRECT against a real third-party SMPP stack and DOCUMENTED for operators. Correctness: the
repo-local docker-compose sandbox launches Kannel on both sides of the chain (front: smsbox HTTP → sqlbox →
bearerbox SMPP-transceiver client; SMSC side: opensmppbox SMPP server → bearerbox → fakesmsc, pgsql DLR
store) with the proxy wedged between as the reverse.mode-b cell — a reproducible debugging playground and a
correctness-proof rig against a REAL unmodified SMPP 3.4 stack (COMP-1 evidence beyond the in-repo mocks and
jSMPP); the composed two-instance forward↔reverse flow (E2E-001) and the packaged-shape journey matrix run
their final conformance. Documentation: the complete operator surface per AD-31/OPS-1 — config reference,
per-mode A/B/C deployment guide (carrying the ROPC removal-track warning and the `docker run` recipe),
runbooks, cipher-allowlist policy, Mode B warning text. Status: Epics 1–6 done; Epic 7
(performance) split out the same day — independent of this epic; **Story 6.1 (the docs half) done
2026-09-13 — the operator surface exists as-built under `docs/` (see Stories); Story 6.2 (the
composed-conformance half) done 2026-09-16, review round 1 closed same date — E2E-001 landed as
three rungs, the journey matrix widened per the ratified decision, the operator docs trued
(see Stories); Story 6.3 (the sandbox capstone) done 2026-09-19 — the Kannel rig, the compose
Keycloak, the host-run launch recipe, the four live-executed correctness journeys, the T5 docker
combo runbooks, and the T6 operator-first docs pass under
`sandbox/`, closed out with the catalog rows and the Gradle-inert GREEN build (see Stories)**.

## Stories

*(Execution order set by owner 2026-09-12: docs → conformance → sandbox — the sandbox, created first, was
renumbered 6.1→6.3 so number = execution order, the repo convention.)*

- 6.1 — operator docs surface (AD-31/OPS-1): config reference, per-mode deployment guide (ROPC warning +
  `docker run` recipe seed, BH15), runbooks, cipher-allowlist policy page, Mode B warning text; the
  base-image digest-pin policy decision (BH6); `docs/a-1-carrier-test-plan.md` already exists
  (OBS-035/036/037) — refresh, don't re-author. The perf-report page is NOT this story's — Epic 7 authors it.
  **DONE 2026-09-13 (docs-only, four tasks): `docs/configuration.md` (every live `companion.*` key, the
  AD-17 matrix, the retired keys), `docs/deployment-guide.md` (per-cell walkthroughs both shapes, the
  canonical `docker run` recipe, the ROPC three-parter + DAG prerequisite, the BH6 DOCUMENT arm),
  `docs/runbooks.md` + `docs/cipher-allowlist-policy.md` (the deny surface, log/metrics references, Mode A
  ACL isolation, JFR hygiene; the AD-34 defaults + tuning envelope), `docs/README.md` (the index), and the
  A-1 plan refreshed against as-built with the legacy `A1CarrierPlanDocsTest` GREEN. Catalog rows
  OBS-029..034/SEC-065/SEC-049 closed OWNER-AMENDED (page = deliverable, per the 2026-09-10 no-Java-over-md
  rule); nothing in the repo parses any page.**
- 6.2 — composed + packaged-shape conformance: E2E-001 (two-real-instance forward↔reverse Mode C composed
  flow, weekly/manual tier), the DockerRig consolidation into testsupport/ BEFORE this story's third consumer
  (deferred-work BH7), the packaged-shape journey-widening decision (mode A/C cells + auth-DENY journeys —
  deferred-work 5.2 close-out #1), COMP-1/REL-3 finals. Runs BEFORE the sandbox, so its rows ride the
  in-JVM mocks/jSMPP by design (E2E-001's own technique) — no sandbox dependency.
  **DONE 2026-09-16 (T1–T4; review round 1 closed same date — 10 fixes + 2 owner ratifications,
  2 ledger defers; zero main-source, zero Gradle changes): T1 folded the rig
  (`testsupport/DockerRig`, BH7 RESOLVED — drift reconciled, both 5.2 suites byte-identical, the third
  consumer landed at T3 as `launchComposedModeCChain`); T2/T3 landed E2E-001 as THREE suites sharing one
  journey home (`testsupport/ComposedJourney`) — the in-JVM rung `ComposedChainE2eTest` (two full boots,
  the real ROPC verifier over the TLS stand-in — closing the 3.3 ROPC-through-TLS gap — allow / auth-DENY /
  REQUIRE-negative), the JAR rung `ComposedPackagedE2eTest` and the Docker rung `ComposedDockerE2eTest`
  (allow + auth-DENY + the composed REL-3 drain: SIGTERM/`docker stop` → ordered stream → 143 both shapes);
  the journey-widening decision executed per the ratified default (mode C composed + in-session auth-DENY
  in BOTH shapes; mode A stays with `TlsModesLoopbackE2eTest` + the DEPLOY-005 structural-sameness
  argument — a dated scope note on the markers, not a silent drop); T4 trued the operator docs
  (deployment-guide § machine-proven + the conformance-run section, executed from the page; docs/README)
  and closed the catalog/ledger (E2E-001 LANDED with the technique notes, DEPLOY-005's scope honesty
  trued, count stays 254; BH7 + journey-widening + ROPC-through-TLS RESOLVED). COMP-1's independent-stack
  point (the jSMPP allow round) and REL-3's composed drain are stated on the markers.**
- 6.3 — the Kannel sandbox: port the proven `/home/ildar/Documents/smpp-sandbox` compose pattern into the
  repo (`sandbox/`), add the Keycloak the reverse cell's ROPC adjudication requires, document the packaged-jar
  launch recipe, and author the correctness journeys (happy send + DLR round trip, deliver_sm injection,
  enquire_link crossing, fail-closed deny journeys) with expected observations. Last by design — the capstone
  real-stack pass + debugging environment after docs and conformance exist to compare against.
  **DONE 2026-09-17 (T1–T4): `sandbox/` is the self-contained rig — the ported Kannel 1.5.0 chain
  (ONE wiring re-point: the front SMSC dials `host.docker.internal:2775`; plus T3's `smsbox-route`
  MO-routing delta the deliver_sm journey itself surfaced), the compose Keycloak 26.7.0 mirroring
  `KeycloakFixture`'s realm (generated secret fetched by path, AD-18), the host-run packaged-jar
  launch recipe (§5, machine-executed: `startup_summary` + Mode B banner + the couple in logs and
  `/metrics`, with the live wrong-port/secret/Keycloak-down mutations), the four correctness
  journeys (§6) and the debugging guide (§7), every observation executed live on 2026-09-17's rig;
  the journeys landed as catalog rows E2E-002..005 (manual-rig ops-tier, the OBS-035/037 precedent);
  `./gradlew clean build --console=plain` GREEN with zero Gradle-file changes. No proxy defect
  surfaced via Kannel (nothing bounced); the two Kannel-side quirks (fakesmsc's glibc double-free on
  bearerbox restart; opensmppbox answering its own credential refusal with the same 0x0D the AD-33
  collapse uses) are README interop notes — not actionable, no deferred-work entry.**

## Requirements & Constraints

- **The sandbox is developer/operator tooling, not shipped product:** it lives under `sandbox/`, changes zero
  main-source lines, and stays inert to Gradle (`clean build` untouched). Its secrets follow AD-18
  (file paths) even locally — the sandbox is also a debug replica of the deploy contract, never a place where
  a secret value "is just sandbox data".
- **The correctness proof is the reproducible journey, honestly labeled:** like the A-1 carrier plan
  (OBS-035/037, ops-tier), the sandbox's proof artifact is documented journeys with expected observations at
  each hop — not a CI-gated suite. Automation of any journey (e.g. a Docker-gated interop row) is an explicit
  dispatch decision, not a default.
- **Kannel is a REAL stack, not an oracle:** findings that contradict the proxy's behavior are debugged, not
  tuned away — a genuine proxy defect found via the sandbox bounces to the owning epic's story (the epics.md
  honest-exception pattern); a genuine Kannel quirk gets documented in the sandbox README as a known
  interop note (COMP-1 context).
- **The Mode B plaintext posture is the sandbox's cell, accepted:** reverse.mode-b (plaintext ingress +
  plaintext SMSC dial per [B]) is exactly what the chain runs — the `CompanionModeBWarning` banner is part of
  the documented launch, the accepted-risk stance it names.
- **AD-17 fail-closed holds in the sandbox:** no auth-bypass switch exists and none is added — the rig
  includes a real Keycloak because the reverse cell's ROPC adjudication requires one; the deny journeys are
  part of the proof, not an inconvenience.
- **No perf measurement here** (Epic 7 owns it): the sandbox README must not publish numbers; k6/load tooling
  stays out of this story.

## Technical Decisions

- **Proxy on the host, Kannel in compose** (the example's own `host.docker.internal` pattern): the front
  bearerbox's SMPP client dials the proxy's host ingress (2775, the SMPP-standard port); the proxy's egress
  dials the published opensmppbox port (14567). Host-run `java -jar` keeps debugger/flag-tweak access — the
  point of a sandbox. A compose-side proxy service (the Epic-5 distroless image) is a documented optional
  variant, not the primary.
- **Kannel 1.5.0 pinned source build** exactly per the example's Dockerfile (gateway tarball + opensmppbox +
  sqlbox + fakesmsc addons; UBI10 builder/minimal runtime) — reproducible, no floating tag.
- **Keycloak in compose mirrors `KeycloakFixture`'s realm shape** (DAG enabled, confidential client) so the
  sandbox's IdP matches the test-tier one the proxy already proves against; the client secret rides a
  gitignored file consumed by path (AD-18).
- **DockerRig consolidation (6.2) follows the 4.2 fixture precedent** — consolidate into `testsupport/`
  before the third consumer, never after.
- **No CI** (owner 2026-09-11) — the sandbox README is the run book; nothing wires into pipelines.

## Cross-Story Dependencies

- **Depends on Epic 5 (done):** the packaged jar + operator flag contract (the sandbox launches the real
  artifact), the Docker shape for the optional compose-side variant.
- **Execution order is 6.1 → 6.2 → 6.3** (owner 2026-09-12: docs first — the as-built system documented
  while fresh; the sandbox last as the capstone). 6.1 (done) carried the three 5.2 defers as routed — the
  `docker run` recipe AUTHORED in its deployment guide (BH15 resolved), the BH6 base-image policy DOCUMENTED
  (the mutable-tag arm, resolved), and the journey-widening evidence POINTER + the BH7 DockerRig note both
  visibly re-homed to 6.2 in the deferred-work ledger (the decisions remain 6.2's) — plus the ROPC
  removal-track warning (the party-mode carry-forward, catalog row OBS-033); its runbooks wrote the
  deny-surface/debugging content from test evidence (the sandbox arrives after — a dated addendum story may
  follow if its observations earn one).
- **Epic 7 (performance) is independent** — split out 2026-09-12; it authors its own perf-report page, so
  6.1 never waits on numbers.
- The test-design catalog's E2E-001 row is the AC-level source for 6.2; the sandbox journeys land as dated
  catalog rows (COMP/E2E-flavored, ops-tier labels) with 6.3's close-out.
