---
title: 'Story 6.3 — the Kannel sandbox: a real-SMPP docker-compose rig for debugging and correctness proof'
type: 'feature'
created: '2026-09-12'
status: 'ready-for-dev'
route: 'dispatch'
baseline_commit: 2f2b0e81444fdb8256fcf0a208d058385ea9074d
review_loop_iteration: 0
context:
  - {project-root}/_bmad-output/implementation-artifacts/epic-6-context.md
  - {project-root}/_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The proxy's SMPP interop evidence rests entirely on in-repo mocks (`MockSmsc` on our own codec) plus jSMPP as the independent oracle — no REAL third-party SMPP stack has ever talked to it. Debugging relay/adjudication behavior against a realistic peer (real bind transceiver, real enquire_link keepalive, real DLR machinery, real SMPP quirks) has no reproducible environment inside the repo. A proven pattern exists OUTSIDE it: `/home/ildar/Documents/smpp-sandbox` — the pre-project origin playground whose README plan item 3 is literally this proxy ("k6 -[http]-> smsbox <-[smpp]-> proxy <-[smpp]-> fakesmsc") — with a docker-compose chain of Kannel 1.5.0 on both sides (front: smsbox HTTP + sqlbox + bearerbox SMPP client; SMSC side: opensmppbox + bearerbox + fakesmsc, postgres DLR store) that has never been ported in.

**Approach:** Port that proven pattern into the repo as a self-contained `sandbox/` — `docker compose up` launches pg + both Kannel sides with healthchecks (the front bearerbox's SMPP-transceiver `smsc = smpp` config pointed at the PROXY's host ingress instead of straight at opensmppbox), plus a Keycloak service the reverse cell's ROPC adjudication requires (AD-17 fail-closed — no auth-bypass exists, none is added). The proxy runs on the host as the packaged jar under the operator flag set (reverse.mode-b: plaintext ingress + plaintext SMSC dial — exactly the [B] posture; the Mode B warning banner is part of the documented accepted-risk launch). Author the correctness journeys with expected observations per hop: the happy send (curl `sendsms` with `dlr-mask=31` → `submit_sm` relayed verbatim through the proxy → fakesmsc receipt → DLR round trip → postgres row + Kannel status pages show the paired sessions), `deliver_sm` injection toward the ESME, `enquire_link` keepalive crossing the relay, and the fail-closed deny journeys (wrong smpp-logins credential → SMSC-originated non-ROK forwarded verbatim per AD-32 case 4; bad OIDC credential → the AD-33 collapsed generic deny on the wire, rich reason only in JSON logs). The proof artifact is the reproducible journey documentation (the A-1 carrier-plan precedent, ops-tier) — journey automation is an explicit dispatch decision, not a default.

## Boundaries & Constraints

**Always:**
- Self-contained repo-local `sandbox/` — compose file, the Kannel 1.5.0 pinned-source Dockerfile (exactly the example's: gateway tarball + opensmppbox + sqlbox + `test/fakesmsc`, UBI10 builder/minimal runtime), `conf/`, `init.sql` (DLR tables), README. Reproducible from a clean checkout: README goes zero → first journey.
- The sandbox launches the REAL artifact: `java -jar proxy.jar` under the ONE operator flag set (`docs/operator-jvm-flag-contract.md`, the `PackagedBootSmokeTest` launch-constant idiom) with reverse.mode-b args (`TestCompanionConfigs`-shaped) — ingress 2775 on the host, egress → the published opensmppbox 14567, OIDC → the compose Keycloak.
- Secrets follow AD-18 even here: the OIDC client secret rides a gitignored FILE consumed by path — the sandbox is a debug replica of the deploy contract, never a place where a secret value is "just sandbox data".
- Correctness journeys are documented with expected observations at each hop (wire behavior named by AD: verbatim forward, collapsed deny, couple visibility in logs/`/metrics`) — a journey that cannot name its expected observation is not shipped.
- Findings discipline: a proxy defect surfaced via Kannel bounces to the owning epic (the epics.md honest exception) — recorded in deferred-work, never patched inside the sandbox; a Kannel quirk becomes a README interop note (COMP-1 context).
- `./gradlew clean build` stays GREEN and untouched — the sandbox is inert to Gradle (no test wiring, no task changes).

**Never:**
- No main-source changes of any kind (no auth-bypass switch, no logging tweaks for the sandbox's convenience — the JSON-lines + `/metrics` surfaces as-shipped ARE the debugging surface being proven).
- No full-chain automation into the test suites by default (a Docker-gated interop row may extract later — an owner decision at dispatch or in 6.2; this story ships the compose rig + journeys).
- No perf measurement or numbers (Epic 7 owns measurement; the README must not publish throughput/latency claims); no k6/load tooling.
- No CI wiring (none exists, owner 2026-09-11); no release/publish tooling.
- No docs/ operator-surface authoring beyond the sandbox README (6.1 owns `docs/`; the README is developer tooling documentation).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Rig boot | `docker compose up` in `sandbox/` | pg + front (bearerbox/smsbox/sqlbox) + SMSC side (bearerbox/opensmppbox/fakesmsc) + Keycloak all reach healthy (curl-able admin status pages, Keycloak realm ready) | A healthcheck that never greens = rig bug → README's troubleshooting table, not a silently dropped service |
| Proxy boot in the chain | `java -jar` reverse.mode-b (2775 ingress, egress 14567, OIDC → compose Keycloak, secret file) | `startup_summary` JSON line; Mode B WARN banner visible (the accepted-risk launch); front bearerbox's SMPP transceiver binds through the proxy → couple visible in proxy logs + `relay_binds_accepted_total` in `/metrics` | Misconfiguration refuses per AD-17 (the sandbox documents the refusal as a journey precondition, never works around it) |
| Happy send + DLR | `curl ".../cgi-bin/sendsms?...&dlr-mask=31&to=...&text=hello"` | `submit_sm` relayed VERBATIM through the proxy (fakesmsc/opensmppbox receipt), DLR returned through the chain, postgres DLR row transitions, status pages show paired sessions | Submit lost/duplicated/corrupted = transit-integrity defect → bounce (REL-1), never tuned away |
| deliver_sm toward ESME | Injection via the fakesmsc stdin channel (the example's tty-attached service) | `deliver_sm` rides the relay back to the originating front bind (the A-1 session-affinity property against a real stack) | Wrong-leg delivery = affinity defect → bounce |
| enquire_link keepalive | Kannel's SMPP client keepalive interval (front conf) | Keepalive PDUs cross the coupled pair opaque-forwarded; the session stays up across idle windows (the accepted-risk constraint: keepalive interval vs. `pre-couple-idle-timeout` documented in the README) | Post-couple `enquire_link` is opaque relay by design (AD-3/AD-32) — no proxy response synthesis, ever |
| Wrong SMSC credential | Front conf's `smsc-username/password` ≠ `smsc-users.txt` | opensmppbox's non-ROK `bind_resp` forwarded VERBATIM to the front (AD-32 case 4 — the SMSC is the sole credential authority); both legs torn down | A synthesized/collapsed response here would violate the verbatim contract → defect |
| Bad OIDC credential | Proxy's ROPC client credential wrong at Keycloak | Bind denied with ONE generic failure code on the wire (AD-33 collapse); the rich reason lives in the JSON logs only | Distinct wire codes = enumeration oracle defect → bounce |
| Sandbox teardown | `docker compose down` (volumes kept per README guidance) | Clean teardown; the host-run proxy SIGTERM drains per AD-22 (already proven in 5.1 — re-observed here as part of the launch recipe) | — |

**Decisions (owner, 2026-09-12, to ratify or amend at dispatch):**
- Proxy on the HOST (debugger/flag access — the sandbox's purpose), Kannel + pg + Keycloak in compose, wired via `host.docker.internal` exactly as the example does it. A compose-side proxy service (the Epic-5 distroless image) is documented as an optional variant only.
- Keycloak dev-mode service mirroring `KeycloakFixture`'s realm shape (DAG enabled, confidential client, the proxy's ROPC flow) — realm export checked into `sandbox/`, the client secret in a gitignored file by path (AD-18).
- Kannel 1.5.0 pinned-source build ported byte-for-byte from the example's Dockerfile (including the automake-1.11 symlink bootstrap quirk and the pgsql DLR wiring) — no version drift, no distro swap.
- Port map: front smsbox HTTP 8080, admin 13000/14000, opensmppbox 14567 published (proxy egress target), proxy ingress host:2775 (the SMPP-standard port; the ONE conf delta from the example — front `smsc` host/port re-pointed from 14567 to `host.docker.internal:2775`).

</frozen-after-approval>

## Code Map

- `/home/ildar/Documents/smpp-sandbox/sandbox/compose.yml` -- the proven 7-service chain (pg w/ healthcheck, front-bearer-box/front-sql-box/front-sms-box, smsc-bearer-box/smsc-opensmpp-box/smsc-fake-smsc; `extra_hosts: host.docker.internal:host-gateway` throughout; healthchecks via the admin `status.txt` endpoints) — the porting source; add the Keycloak service + re-point the front SMSC config at the proxy.
- `/home/ildar/Documents/smpp-sandbox/kannel/Dockerfile` -- the Kannel 1.5.0 pinned-source build (UBI10 builder: gateway-1.5.0.tar.gz, `--with-pgsql`, `test/fakesmsc` copied, addons opensmppbox + sqlbox; UBI10-minimal runtime w/ pgsql15-libs) — port as-is.
- `/home/ildar/Documents/smpp-sandbox/sandbox/conf/` -- `front-kannel.conf` (the SMPP-transceiver `group = smsc` that dials the proxy: `smsc-username/-password`, `interface-version = 34`, `transceiver-mode = true` — re-point `host/port` to the proxy ingress), `smsc-opensmppbox.conf` (opensmppbox on 14567, `smpp-logins`, `route-to-smsc = FAKE1`, pgsql DLR), `smsc-kannel.conf` (SMSC-side bearerbox + fake SMSC `FAKE1` @ 10004), `smsc-users.txt` (`usr1 pwd1 smsc1 *.*.*.*`), `db.conf`, `front-sqlbox.conf`.
- `/home/ildar/Documents/smpp-sandbox/sandbox/init.sql` -- the pgsql DLR tables (front/smsc bearer + smpp DLR tables) — port with the compose's `docker-entrypoint-initdb.d` mount.
- `proxy/src/test/java/smpp/companion/proxy/bootstrap/PackagedBootSmokeTest.java` -- the packaged-jar launch idiom (operator flag set from the Java-side launch constant, subprocess handling, `scrape(port)`, SIGTERM observation) — the README's proxy-launch recipe documents the same commands by hand.
- `proxy/src/test/java/smpp/companion/proxy/config/TestCompanionConfigs.java` -- the reverse-B arg shape (`reverseB(dir)` + `args()`) the sandbox's launch recipe mirrors for a real directory of secret files.
- `proxy/src/test/java/smpp/companion/proxy/security/KeycloakFixture.java` + `proxy/src/test/resources/keycloak/certs/` -- the realm shape the compose Keycloak mirrors (DAG enabled, confidential client; the 3.1 probe's verdict pinned DAG present in 26.x, pin ≥26.7.0).
- `docs/operator-jvm-flag-contract.md` -- the ONE flag set + floor+mirror rule the sandbox launch cites (the README links it rather than duplicating the set).
- `proxy/src/main/java/smpp/companion/proxy/config/CompanionModeBWarning.java` -- the WARN JSON banner the documented launch shows and the README explains (the accepted-risk stance).
- `proxy/src/test/java/smpp/companion/proxy/relay/MockSmsc.java` / `JsmppSmscServer.java` -- what the sandbox COMPLEMENTS, not replaces: in-repo mock + jSMPP oracle stay the automated oracles; Kannel adds the real-stack, human-driven correctness tier.
- `docs/a-1-carrier-test-plan.md` -- the ops-tier journey-documentation precedent (oracle, preconditions, PASS/FAIL, evidence) the sandbox README's journey sections follow in miniature.
- `proxy/build.gradle.kts` -- NOTHING here changes (the sandbox is Gradle-inert; this entry exists to say so explicitly).

## Tasks & Acceptance

**Execution:**
- [ ] **T1 — the Kannel rig in-repo** — `sandbox/` with the ported Dockerfile, `conf/` (the ONE delta: front SMSC re-pointed at `host.docker.internal:2775`), `init.sql`, and `compose.yml` (pg + both Kannel sides + healthchecks, ports 8080/13000/14000/14567 published, fakesmsc tty-attached for injection). Verify from a clean checkout: `docker compose up` → every healthcheck green; `docker compose config` validates. Mutation: any service's healthcheck removed or conf broken → the README's bring-up table names the failure instead of hiding it.
- [ ] **T2 — Keycloak + the proxy launch recipe** — Compose Keycloak service (dev mode, realm export mirroring `KeycloakFixture`: DAG enabled, confidential client; pin ≥26.7.0 per the 3.1 verdict) + the gitignored client-secret file by path (AD-18); README section: build the jar (`./gradlew :proxy:bootJar`), the `java -jar` launch with the operator flag set + reverse.mode-b args (ingress 2775, egress 14567, OIDC → compose Keycloak, secret file path), expected `startup_summary` + Mode B banner, and the front bearerbox binding THROUGH the proxy (couple in logs + `/metrics`). Mutation: launch recipe pointed at a stale jar or wrong port → the bind never couples → the recipe's expected-observation step fails loudly.
- [ ] **T3 — the correctness journeys + debugging guide** — README journeys, each with expected observations per hop: happy send + DLR round trip (postgres row + status pages); `deliver_sm` injection toward the ESME; `enquire_link` crossing the coupled pair (with the keepalive-vs-`pre-couple-idle-timeout` note); the two deny journeys (wrong SMSC credential → AD-32 case-4 verbatim non-ROK forward; bad OIDC credential → AD-33 collapsed generic deny on the wire, rich reason in JSON logs only); the debugging entry-point table (Kannel admin `status.txt`, log levels, proxy `/metrics` + JSON lines, pg tables, fakesmsc stdin). Mutation: a journey whose expected observation is unstated or unobservable → not shipped (the Always rule bites at review).
- [ ] **T4 — proofs, catalog rows, ledger** — `./gradlew clean build --console=plain` GREEN untouched (the Gradle-inert claim verified, not assumed); sandbox journey rows land in the catalog as dated ops-tier entries (COMP-1/E2E-flavored, labeled manual-rig like OBS-035/037); any Kannel-quirk interop notes recorded in the README + deferred-work if actionable; `epic-6-context.md` regenerated to as-built.

**Acceptance Criteria:**
- Given a clean checkout and Docker, when the README's bring-up is followed, then every compose service reaches healthy and the front bearerbox's SMPP transceiver binds through the host-run proxy — the couple visible in the proxy's logs and `/metrics`.
- Given the bound chain, when a `sendsms` with `dlr-mask=31` is sent, then the `submit_sm` relays verbatim through the proxy, the DLR completes the round trip, and the journey's expected observations (postgres row, status pages) hold at every hop.
- Given a `deliver_sm` injected at the SMSC side, then it rides the relay back to the originating front bind (session affinity against a real stack).
- Given the deny journeys, when the SMSC credential is wrong, the non-ROK `bind_resp` forwards verbatim (AD-32 case 4); when the OIDC credential is bad, the wire carries one generic failure code (AD-33) with the rich reason in JSON logs only.
- Given the sandbox directory, when `./gradlew clean build` runs, then the build is GREEN with zero Gradle changes from this story.

## Implementation Notes

## Spec Change Log

## Review Triage Log

## Design Notes

- The proxy is the ONLY piece on the host — everything compose-side already speaks `host.docker.internal` in the example, so the ONE wiring delta is the front `smsc` group's `host/port`. Keep it that way: a sandbox with two deltas is a different rig.
- The reverse.mode-b cell choice is load-bearing, not convenience: plaintext ingress + plaintext SMSC dial is the [B] topology's mode-B posture exactly, needs no certs, and its banner is the documented accepted risk — the sandbox thereby doubles as a live demo of the AD-17/AD-18/Mode-B contract pages.
- `enquire_link` is Kannel's keepalive, not ours: post-couple it relays opaque (AD-3/AD-32 — the proxy never synthesizes `enquire_link_resp`); pre-couple it bare-closes. The README documents both windows so a keepalive-driven disconnect during adjudication is understood, not misread as a defect.
- The deny journeys double as the sandbox's most valuable debugging content: they show WHERE each failure surfaces (wire vs. log vs. metric) — the operational skill the runbooks (6.1) will formalize.
- One-task-per-conversational-step, one commit per task (repo rule). The rig (T1) is committed runnable; T2/T3 build on it in order.

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN, zero changes to any Gradle file (the Gradle-inert claim is itself the check).
- `docker compose -f sandbox/compose.yml config` -- expected: valid; then `docker compose up` per the README reaches all-healthy.

**Manual checks (if no CLI):**
- Follow the README from zero: compose up → proxy launch → happy-send journey → deny journeys — every expected observation in the journey tables holds.

## Dev Agent Record

### Agent Model Used

### Debug Log References

### Completion Notes List

### File List
