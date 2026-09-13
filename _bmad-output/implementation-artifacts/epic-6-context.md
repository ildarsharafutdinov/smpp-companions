# Epic 6 Context: Correct and document the proxy — the Kannel sandbox, composed conformance, and the operator docs surface

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->
<!-- Compiled 2026-09-12 (the Epic 6/7 split, owner direction same date): the former Epic 6's performance half
     moved to Epic 7 ("epic 7 focuses on performance measurement"); THIS epic keeps "having the proxy documented
     and corrected" plus the owner-directed Kannel docker-compose sandbox for debugging and correctness proof
     (example: /home/ildar/Documents/smpp-sandbox, the repo's pre-project origin playground, whose README plan
     item 3 is literally this proxy). The three 5.2-closure defers re-homed here stay here (journey-widening,
     DockerRig consolidation, docker-run recipe). Same-date execution order set: docs → conformance → sandbox
     (the sandbox story, created first as 6.1, renumbered to 6.3 — see Stories). -->
<!-- Regenerated to as-built 2026-09-13 (Story 6.1 T4): 6.1 is implemented (in code review) — the AD-31 surface exists under docs/
     (README.md indexes configuration.md, deployment-guide.md, runbooks.md, cipher-allowlist-policy.md beside
     the flag-contract page; a-1-carrier-test-plan.md refreshed in place); the 5.2 defers it carried are
     ledgered (BH15 authored + BH6 documented = resolved; journey-widening + BH7 visibly re-homed to 6.2). -->

## Goal

Make the proxy CORRECT against a real third-party SMPP stack and DOCUMENTED for operators. Correctness: the
repo-local docker-compose sandbox launches Kannel on both sides of the chain (front: smsbox HTTP → sqlbox →
bearerbox SMPP-transceiver client; SMSC side: opensmppbox SMPP server → bearerbox → fakesmsc, pgsql DLR
store) with the proxy wedged between as the reverse.mode-b cell — a reproducible debugging playground and a
correctness-proof rig against a REAL unmodified SMPP 3.4 stack (COMP-1 evidence beyond the in-repo mocks and
jSMPP); the composed two-instance forward↔reverse flow (E2E-001) and the packaged-shape journey matrix run
their final conformance. Documentation: the complete operator surface per AD-31/OPS-1 — config reference,
per-mode A/B/C deployment guide (carrying the ROPC removal-track warning and the `docker run` recipe),
runbooks, cipher-allowlist policy, Mode B warning text. Status: Epics 1–5 done (`2f2b0e8`); Epic 7
(performance) split out the same day — independent of this epic; **Story 6.1 (the docs half)
implemented 2026-09-13, in code review — the operator surface exists as-built under `docs/`
(see Stories)**.

## Stories

*(Execution order set by owner 2026-09-12: docs → conformance → sandbox — the sandbox, created first, was
renumbered 6.1→6.3 so number = execution order, the repo convention.)*

- 6.1 — operator docs surface (AD-31/OPS-1): config reference, per-mode deployment guide (ROPC warning +
  `docker run` recipe seed, BH15), runbooks, cipher-allowlist policy page, Mode B warning text; the
  base-image digest-pin policy decision (BH6); `docs/a-1-carrier-test-plan.md` already exists
  (OBS-035/036/037) — refresh, don't re-author. The perf-report page is NOT this story's — Epic 7 authors it.
  **IMPLEMENTED 2026-09-13, in code review (docs-only, four tasks): `docs/configuration.md` (every live `companion.*` key, the
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
- 6.3 — the Kannel sandbox: port the proven `/home/ildar/Documents/smpp-sandbox` compose pattern into the
  repo (`sandbox/`), add the Keycloak the reverse cell's ROPC adjudication requires, document the packaged-jar
  launch recipe, and author the correctness journeys (happy send + DLR round trip, deliver_sm injection,
  enquire_link crossing, fail-closed deny journeys) with expected observations. Last by design — the capstone
  real-stack pass + debugging environment after docs and conformance exist to compare against.

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
