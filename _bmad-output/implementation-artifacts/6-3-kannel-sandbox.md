---
title: 'Story 6.3 — the Kannel sandbox: a real-SMPP docker-compose rig for debugging and correctness proof'
type: 'feature'
created: '2026-09-12'
status: 'in-progress'
route: 'dispatch'
baseline_commit: 73e4813daf1138c7825041b65f2707518bbcf11f
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
- [x] **T1 — the Kannel rig in-repo** — `sandbox/` with the ported Dockerfile, `conf/` (the ONE delta: front SMSC re-pointed at `host.docker.internal:2775`), `init.sql`, and `compose.yml` (pg + both Kannel sides + healthchecks, ports 8080/13000/14000/14567 published, fakesmsc tty-attached for injection). Verify from a clean checkout: `docker compose up` → every healthcheck green; `docker compose config` validates. Mutation: any service's healthcheck removed or conf broken → the README's bring-up table names the failure instead of hiding it.
- [x] **T2 — Keycloak + the proxy launch recipe** — Compose Keycloak service (dev mode, realm export mirroring `KeycloakFixture`: DAG enabled, confidential client; pin ≥26.7.0 per the 3.1 verdict) + the gitignored client-secret file by path (AD-18); README section: build the jar (`./gradlew :proxy:bootJar`), the `java -jar` launch with the operator flag set + reverse.mode-b args (ingress 2775, egress 14567, OIDC → compose Keycloak, secret file path), expected `startup_summary` + Mode B banner, and the front bearerbox binding THROUGH the proxy (couple in logs + `/metrics`). Mutation: launch recipe pointed at a stale jar or wrong port → the bind never couples → the recipe's expected-observation step fails loudly.
- [x] **T3 — the correctness journeys + debugging guide** — README journeys, each with expected observations per hop: happy send + DLR round trip (postgres row + status pages); `deliver_sm` injection toward the ESME; `enquire_link` crossing the coupled pair (with the keepalive-vs-`pre-couple-idle-timeout` note); the two deny journeys (wrong SMSC credential → AD-32 case-4 verbatim non-ROK forward; bad OIDC credential → AD-33 collapsed generic deny on the wire, rich reason in JSON logs only); the debugging entry-point table (Kannel admin `status.txt`, log levels, proxy `/metrics` + JSON lines, pg tables, fakesmsc stdin). Mutation: a journey whose expected observation is unstated or unobservable → not shipped (the Always rule bites at review).
- [x] **T4 — proofs, catalog rows, ledger** — `./gradlew clean build --console=plain` GREEN untouched (the Gradle-inert claim verified, not assumed); sandbox journey rows land in the catalog as dated ops-tier entries (COMP-1/E2E-flavored, labeled manual-rig like OBS-035/037); any Kannel-quirk interop notes recorded in the README + deferred-work if actionable; `epic-6-context.md` regenerated to as-built.

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

glm-5.2 (Claude Code dispatch agent), 2026-09-17, T1 only.
glm-5.2 (Claude Code dispatch agent), 2026-09-17, T2 only.
glm-5.2 (Claude Code dispatch agent), 2026-09-17, T3 only (this run).
glm-5.2 (Claude Code dispatch agent), 2026-09-17, T4 only (this run).

### Debug Log References

- `docker compose -f sandbox/compose.yml config` — VALID (spec's verification command form).
- `docker compose up -d --build` — full cache hit on the playground's layers; all 7 services up;
  `pg`, `front-bearer-box`, `smsc-bearer-box` reach `(healthy)` in order; `docker compose ps`
  shows the rest running. Build `Apr 25 2026`, Kannel `1.5.0`.
- Front status page: `smsbox:sqlbox1` + `smsbox:smsbox1` on-line; DLR `using pgsql storage`; SMSC
  connections empty with the expected 10 s reconnect loop toward `host.docker.internal:2775`
  (the conf delta live). SMSC status page: `FAKE1 (online ...)`. `sendsms` curl → HTTP 202.
  pg `\dt`: the three init.sql DLR tables + sqlbox's `front_sms_log`/`front_sms_insert`.
- opensmppbox: `Connected to bearerbox at host.docker.internal port 14001`; 14567 TCP-listening.
- Mutation run (live): bogus `group = nonexistent-group` appended to `conf/front-kannel.conf` →
  bearerbox logs `Group 'nonexistent-group' is no valid group identifier. Error found on line 58
  of file '/etc/kannel/front-kannel.conf'`, exits 1, container `exited` (healthcheck never
  greens); dependents `front-sql-box`/`front-sms-box` exit 0 with it. Conf restored
  byte-identical (`cmp`), `docker compose up -d` → full chain healthy again. The README's
  bring-up table carries the observed wording.
- Teardown probes: a DLR row does NOT survive `down`/`up` (anonymous volume — fresh store,
  init.sql re-runs) but DOES survive `stop`/`start`; README §6 states this verified behavior.
  Final teardown `down -v` — no containers, network, or volumes left.

T2 (2026-09-17):

- `docker compose -f sandbox/compose.yml config` — VALID (re-checked after the keycloak service
  landed; the spec's verification command form).
- `docker compose up -d --build` — the 8-service rig: Kannel layers full cache hit; `keycloak`
  (quay.io/keycloak/keycloak:26.7.0, already pulled by the test tier) reaches `(healthy)` in ~17 s
  (TCP-connect probe); `Realm 'smpp-companions' imported`, `Import finished successfully`.
- Host discovery curl (`--cacert keycloak/certs/ca.pem`) → 200 with
  `"issuer":"https://localhost:8443/realms/smpp-companions"` and `"password"` in
  `grant_types_supported`.
- **The generated-secret design proven live:** the realm export (no `secret` field) imported with
  a GENERATED client secret; fetched via `kcadm.sh config truststore … --trustpass` (positional
  path — `--truststore-path` is NOT a valid option; kcadm rejects self-signed without the store) →
  `config credentials` → `get clients/$CID/client-secret`; written to the gitignored
  `sandbox/secrets/oidc-client-secret` (`git check-ignore` names `.gitignore:39:sandbox/secrets/`;
  `git status` never sees it).
- `./gradlew :proxy:bootJar` — BUILD SUCCESSFUL (UP-TO-DATE: the jar was current; Gradle's input
  tracking is the no-stale-jar guarantee the README cites).
- **The recipe, executed verbatim from README §5.2:** Mode B WARN banner JSON line →
  `startup_summary` (`role reverse`, `mode b`, `smpp_bind_host 0.0.0.0`, `smpp_bind_port 2775`,
  `metrics_port 9090`, `routing_system_ids []`, AD-30 interlock
  `memory_budget_bytes == direct_memory_ceiling_bytes == 6442450944`) → **~11 s later
  `bind_accept system_id=usr1 outcome=coupled`** — the front bearerbox bound THROUGH the
  host-run proxy (ROPC Allow at the compose Keycloak → egress dial to opensmppbox 14567 → ROK).
- The couple's three vantage points, all observed: `/metrics` `relay_binds_unknown_total 1.0`
  (the honest reverse-cell observable — no routing table, AD-19; see the README §5.3 honesty note
  vs the spec I/O matrix's `relay_binds_accepted_total` phrasing); front status page
  `smsc1 … SMPP:host.docker.internal:2775/2775:usr1:smsc1 (online …)`; opensmppbox log's
  `bind_transceiver_resp` dump `command_status: 0`. Post-couple keepalive:
  `relay_pdus_total{INGRESS}`/`{EGRESS}` = 1 each (Kannel's `enquire_link` crossing both ways).
- **Mutation run (live, wrong egress port 14568):** proxy stdout SILENT after `startup_summary`
  (no `bind_accept` ever — and no `bind_reject`: the verdict was Allow, the failure is the
  post-verdict dial, AD-27 pinned triggers); front log every 10 s
  `SMSC rejected login to transmit, code 0x0000000d (Bind Failed)` (the AD-33 collapse on the
  wire); `/metrics` `relay_connections_closed_total{direction="INGRESS",reason="EGRESS_CONNECT_FAILED"}`
  climbing (10.0 after 10 retries), `relay_binds_*` at 0. Restore launch → couple again within
  one retry. The stale-jar arm is structurally prevented by bootJar's input tracking (documented,
  not mutated).
- **Deny arms (live, second rig cycle — also re-proving the §5.1 regeneration semantics: the
  fresh container generated a NEW secret, re-fetched per the documented steps):** (1) wrong
  client secret → `bind_reject` lines `verdict":"DenyInvalid"` +
  `bind_resp_command_status":"0x0000000D"`, `relay_binds_rejected_total` climbing, front wire
  `code 0x0000000d (Bind Failed)`; (2) `docker compose stop keycloak` with the correct secret →
  `bind_reject` `verdict":"DenyIndeterminate"`, SAME `0x0000000D` on the wire — the two arms are
  wire-indistinguishable (AD-33; no IdP-availability enumeration), distinguished only by the
  verdict field in the proxy's JSON log lines. Both arms' signatures are in README §5.4.
- SIGTERM teardowns (2×, both launches with the coupled pair live): the OBS-020 drain WARN —
  `shutdown drain deadline (PT10S) expired — force-closed 1 live pair(s) as SHUTDOWN_DRAIN` —
  then exit **143** (captured on the exec-form run; Kannel never half-closes, so the drain always
  force-closes at the deadline — documented as expected).
- Final teardown `docker compose down -v` — no containers, network, or volumes left; no proxy
  process running.

T3 (2026-09-17):

- Rig re-bring-up: `docker compose up -d --build` → all 8 services up; pg + both bearerboxes +
  keycloak `(healthy)`; `Realm 'smpp-companions' imported`; the §5.1 bootstrap re-run against the
  fresh container (regenerated secret fetched via kcadm into the gitignored file — `git
  check-ignore` names it); `./gradlew :proxy:bootJar` BUILD SUCCESSFUL (UP-TO-DATE); the §5.2
  recipe launched verbatim → Mode B banner + `startup_summary` + `bind_accept … coupled` within
  ~14 s (T2's recipe re-proven on this run's rig before the journeys).
- **§6.1 happy send + DLR round trip (executed live):** `sendsms` with `dlr-mask=31` (no
  `dlr-url` — Kannel accepts; the smsbox logs the harmless `URL <>` ERROR pair) → HTTP 202 `0:
  Accepted for delivery`; pg `front_sms_log` `momt=MT` row (`hello`, `dlr_mask=31`) +
  `front_bearer_dlr` (`mask=31,status=0`) + `smsc_bearer_dlr` (`mask=19`) rows
  (`smsc_smpp_dlr` stays empty); opensmppbox `submit_sm` → `submit_sm_resp` (message_id
  e82bd7c8) → DLR `deliver_sm` (`stat:DELIVRD`, `receipted_message_id:"e82bd7c8"`,
  `message_state: 2`) → `Got PDU: deliver_sm_resp` ROK; fakesmsc `Got message 1:
  <79876543210 79033374423 text hello>`; front `removing DLR from database` + two `momt=DLR`
  rows (`ACK/` mask 8, the `id:…stat:DELIVRD…` text mask 1); status pages `sent: sms 1` /
  `rcvd: dlr 2` (front), FAKE1 `sent: sms 1 / rcvd: dlr 1` (SMSC); metrics +1/+1 per crossing.
- **§6.2 deliver_sm injection (executed live, after the conf delta below):** line syntax pinned
  empirically — `<sender> <receiver> text <message>` (the `text` coding keyword REQUIRED: without
  it fakesmsc still prints `sent message N` but the BEARERBOX rejects with
  `smsc_fake: invalid message syntax from client, ignored`); fed through a fifo held into
  `script -qec "docker attach …"` (plain-pipe attach refused: `cannot attach stdin to a
  TTY-enabled container because stdin is not a terminal`); opensmppbox `Sending PDU:
  deliver_sm` (`source_addr:"79033374423"`, `destination_addr:"79876543210"`) → the FRONT's own
  SMPP dump shows the identical `short_message` octets (`hello from the mobile`) → `Got PDU:
  deliver_sm_resp` ROK; front status `rcvd: sms 1`; metrics +1 EGRESS +1 INGRESS.
- **THE T3 RIG FINDING — the MO-routing delta:** the first injection died queued with
  `WARNING: smsbox_list empty!` — Kannel 1.5.0's `bb_boxc.c` broadcasts MOs only to boxes with
  `boxc_id == NULL`, and opensmppbox registers as `usr1` (`use-systemid-as-smsboxid = true`);
  the playground never routed MOs (its plan never needed them), so the ported conf has no
  `smsbox-route`. Fix: `group = smsbox-route` (`smsbox-id = usr1`, `smsc-id = FAKE1`) added to
  `conf/smsc-kannel.conf` (commented in-file), bearerbox restarted → injection works. Documented
  as deltas-list item 4 in both READMEs + the compose.yml header; three troubleshooting rows
  added (smsbox-route absence, invalid line syntax, fakesmsc crash). `front-kannel.conf` verified
  byte-identical to HEAD after the deny-journey edits (`git diff` names only
  `sandbox/conf/smsc-kannel.conf`).
- Side observations from the restart: restarting `smsc-bearer-box` took fakesmsc down with a
  glibc `free(): double free detected in tcache 2` (Kannel 1.5.0 quirk → interop note in the
  troubleshooting table; `up -d` restores); the couple's teardown while opensmppbox's box link
  dropped showed `relay_connections_closed_total{PEER_HALF_CLOSE}` on both legs then an
  automatic re-couple (bind_accept #2) — the SMSC-flap behavior, named in passing in §6.4's
  metric-shape discussion.
- **§6.3 enquire_link (passive, timed):** first `enquire_link` at couple + 30 s, then one per
  ~30 s (Kannel's default `enquire-link-interval`; the conf sets none); each interval +1 on BOTH
  `relay_pdus_total` legs (the enquire INGRESS + its resp EGRESS — the tag follows the arrival
  leg); opensmppbox/front dump the mirror pair; the session online-time grows without bound. The
  keepalive-vs-`pre-couple-idle-timeout` note written with the live arithmetic (4 s deadline ≪
  30 s interval; Kannel enquires only on a bound session).
- **§6.4 deny journeys (both arms live, both restored):** D1 (`usr2`/`pwd2`: ROPC-valid,
  smsc-users-absent) → proxy stdout SILENT, `BIND_FAILED_NON_ROK` closes +1 per retry on BOTH
  legs, `relay_binds_rejected_total`/`relay_binds_unknown_total` flat, opensmppbox answered its
  OWN `bind_transceiver_resp` `command_status: 13 = 0x0000000d`, `system_id: NULL` (its code
  coincides with the AD-33 collapse — the two arms are wire-identical in THIS rig; the
  verbatim-forward and the discriminator are the dump + the metric shape, stated in the README);
  front wire `code 0x0000000d (Bind Failed)` every 10 s. D2 (`usr1` + wrong password) →
  `bind_reject` `verdict":"DenyInvalid"` + `bind_resp_command_status":"0x0000000D"` per retry,
  `relay_binds_rejected_total` AND `relay_binds_unknown_total` climbing, closes
  `{INGRESS,BIND_REJECTED}`, ZERO `bind_transceiver` at opensmppbox (deny pre-forward), the
  IDENTICAL front wire line. Both reverts re-coupled within one 10 s retry (bind_accept #3/#4).
- **§7 TRACE arm (executed live):** §5.2 relaunched with one more run arg
  `--logging.level.smpp.companion.proxy.relay.pdu=TRACE` → `relayed pdu:
  direction=INGRESS command_id=0x4 length=66 body=0x00000042…` (the `trace-probe` text readable
  in the hex), the `submit_sm_resp` (`command_id=0x80000004`), the DLR `deliver_sm`
  (`command_id=0x5 length=185`) — and ZERO bind-family pdu lines (redacted at every level, as
  shipped). Two SIGTERM teardowns across the run: the OBS-020 drain WARN (PT10S, 1 live pair,
  SHUTDOWN_DRAIN) then a clean exit, re-observed on both launches.
- Final teardown: `docker compose down -v` — no containers, network, or volumes left; no proxy
  process running; the attach holder killed; scratch files removed.

T4 (2026-09-17):

- `./gradlew clean build --console=plain` — **BUILD SUCCESSFUL in 3m 3s**, exit 0, 34 actionable
  tasks: 25 executed, 9 up-to-date. Test-result XML totals: `:codec` 82 tests / 0 failed /
  0 skipped, `:proxy` 439 tests / 0 failed / 0 skipped — **521 total, 0 skipped** (the Docker
  suites ran — the daemon is up on this box). The Gradle-inert claim verified on BOTH axes:
  `git status` names no Gradle file (before and after the build — only `.gitignore`,
  `sandbox/**`, this spec, the catalog, `epic-6-context.md` ever appear), and no build file
  references `sandbox/` (grepped `settings.gradle.kts`, root/`proxy`/`codec` `build.gradle.kts`,
  `gradle.properties`, `buildSrc/` — zero references).
- `docker compose -f sandbox/compose.yml config` — VALID (re-checked at close-out; the spec's
  verification command form; the live all-healthy bring-ups are T1–T3's recorded runs, the last
  torn down `down -v` at T3's end).
- Catalog rows landed: **E2E-002** (happy send + DLR round trip), **E2E-003** (`deliver_sm` MO
  injection — A-1 affinity against a real stack), **E2E-004** (`enquire_link` crossing the
  coupled pair), **E2E-005** (the two deny journeys, AD-32 case 4 vs AD-33) — under a new §8.2
  "The Kannel manual-rig journeys" (E2E-001 got the §8.1 heading beside it), each row labeled
  `[manual rig — Story 6.3]` with a Status bullet naming the live 2026-09-17 execution and its
  README §6 home; the dated Row-additions note added at the top; §1.1/§1.2 tallies amended
  **254 → 258** (E2E 1 → 5, P2 72 → 76, the level-tally e2e column 11 → 15); §9.4's A-1
  testability boundary gained the dated E2E-003 real-stack parenthetical.
- Interop-note sweep (the README half of the ledger item): both T3 quirks present in BOTH
  READMEs — the fakesmsc glibc `double free` row and the zero-byte-probe `Invalid SMPP PDU`
  row in §8's troubleshooting table, the opensmppbox-0x0D wire-identical note in §6.4. Deferred-
  work determination: **neither actionable** — upstream Kannel 1.5.0 behavior / rig properties;
  the only proxy-side "actions" imaginable would be tuning the product for the sandbox, which
  the Always rules forbid. The README interop note IS the terminal disposition the findings
  discipline prescribes → no ledger entry added.
- `epic-6-context.md` regenerated to as-built (the 6.1/6.2 T4 precedent): the dated regeneration
  comment, the Goal status line, the 6.3 DONE summary.

### Completion Notes List

- T1 executed per the one-task-per-conversational-step rule; T2 (Keycloak + proxy launch
  recipe), T3 (journeys + debugging guide), T4 (proofs/catalog/ledger) NOT started.
- Owner mid-T1 additions (2026-09-17, applied by the orchestrator after the T1 diff audit):
  (a) Russian translation `sandbox/README.ru.md` (EN original normative, docs/ru conventions +
  glossary terms; colocated next to the original); (b) the chain schema in both READMEs converted
  ASCII → mermaid; (c) opensmppbox necessity checked — verdict REQUIRED (fakesmsc is a Kannel
  box-protocol CLIENT into the bearerbox, never an SMPP listener; opensmppbox is the rig's only
  SMPP 3.4 server: egress termination + AD-32 case-4 credential authority + SMPP↔box translation
  for the A-1 deliver_sm journey + smsc_smpp_dlr hop) — documented as README §2.1 in both
  languages. Also disclosed: the T1 diff audit staged `sandbox/` intent-to-add (`git add -N`,
  index entries only — no commits).
- Frozen Decision 1 (proxy placement) RATIFIED at dispatch (owner, 2026-09-17): host-run packaged
  jar stays THE launch; the compose-side proxy (Epic-5 distroless image, same hairpin wiring,
  read-only AD-18 secret mount — the shape 6.2's E2E already proved) is DOCUMENTED as an optional
  variant only. T2 therefore delivers a "docker-proxy variant" README section beside the host
  `java -jar` recipe; the mermaid diagram keeps "on the host, packaged jar" (made vertical per
  owner, same day). The why-host-vs-docker rationale is stated in README §1 of both languages
  (debugger/JDK-toolbox/flag access vs deliberately minimal distroless; docker variant not
  rejected — 6.2-proven — just not the debugging posture).
- Owner directive honored: NOTHING committed — no `git add`, no `git commit`; all work sits
  uncommitted in the working tree.
- Deltas from the porting source, all listed in README §7: the ONE conf re-point
  (`front-kannel.conf` `port = 14567 → 2775`, host unchanged; its route-comment diagram trued to
  the proxied topology and anglicized per the repo language rule), the compose project
  `name: smpp-bmad-sandbox` + `build: ./kannel` (self-contained layout). Everything else ported
  byte-identical (`cmp`-verified: Dockerfile, init.sql, db.conf, front-sqlbox.conf,
  smsc-kannel.conf, smsc-opensmppbox.conf, smsc-users.txt).
- Two observed interop notes landed in the README troubleshooting table: zero-byte TCP probes
  of 14567 make opensmppbox log `ERROR: Invalid SMPP PDU received` (probe artifact, box keeps
  serving); Kannel boxes exit cleanly when their bearerbox exits (dependents need `up -d`).
- The Kannel build was a full layer-cache hit (the playground images predate it); a genuinely
  cold build compiles from the pinned source and was NOT re-timed here (no perf numbers by
  contract).
- Gradle inertness at T1 is structural: no build file references `sandbox/` (grepped
  settings/build/buildSrc/proxy/codec) and `git status` shows no Gradle-file changes; the
  formal `./gradlew clean build --console=plain` GREEN check stays with T4 per the task list.

T2 completion notes (2026-09-17):

- T2 executed per the one-task-per-conversational-step rule; T3 (correctness journeys +
  debugging guide) and T4 (proofs/catalog/ledger) NOT started.
- Owner directive honored again: NOTHING committed, no git state mutated — no `git add`, no
  `git commit`; T1's staged index untouched, all T2 work lands in the working tree beside it
  (including the root `.gitignore` edit — a tracked-file working-tree change, uncommitted).
- The Keycloak service mirrors the test-tier `KeycloakContainer`'s VERIFIED launch line
  (`start --import-realm --hostname-strict=false`, pinned 26.7.0, fixture server cert/key,
  HTTPS-only, fixed 8443 bind) with exactly two posture deltas, both commented in
  `compose.yml`: (1) `KC_HTTPS_CLIENT_AUTH` UNSET — the production adapter's IdP SSLContext is
  trust-only (no client cert toward the provider; client auth is the ROPC `client_secret`),
  unlike the test slice; (2) `KC_BOOTSTRAP_ADMIN_*` instead of the deprecated `KEYCLOAK_ADMIN`
  (same semantics, no KC-SERVICES0110 warning). The frozen Decision's "dev-mode" is realized as
  this local admin/admin + self-signed localhost posture; the literal `start-dev` verb was NOT
  used because it would open a plaintext 8080 the rig has no use for (the fixture-verified
  `start` with https-only is the closer mirror).
- Healthcheck finding (live-probed): KC 26.7 serves the MANAGEMENT interface over TLS too —
  `KC_HTTPS_CLIENT_AUTH`/`KC_HTTP_MANAGEMENT_ENABLED=true` notwithstanding, the log says
  `Management interface listening on https://0.0.0.0:9000`, and the image ships no TLS-capable
  client (no curl/wget; kcadm is a JVM fork per probe — too heavy at probe cadence). The
  compose healthcheck is therefore a TCP-connect to 8443 (listener up), and realm READINESS is
  the README §5.1 discovery curl, which the secret bootstrap runs anyway — the T1 pattern
  (healthchecks only where a cheap authoritative probe exists) extended, not weakened.
- The realm export carries TWO users, not one: `usr1`/`pwd1` (happy path — matches BOTH the
  front conf and `smsc-users.txt`, so ROPC and opensmppbox both accept) and `usr2`/`pwd2`
  (T3's wrong-SMSC-credential journey: ROPC-valid, smsc-users-ABSENT — the AD-32 case-4 pair).
  Landed now because a realm edit after a re-create forces the secret re-fetch cycle
  (regeneration semantics documented in README §5.1/§7).
- AD-18 realization: the realm export deliberately has NO `secret` field → Keycloak GENERATES
  one at import (verified live) → fetched via kcadm into the gitignored
  `sandbox/secrets/oidc-client-secret` (`.gitignore` gains `sandbox/secrets/`). The committed
  `keycloak/certs/` PKI is fixture-tier test material copied byte-identical from the committed
  test resources (`cmp`-verified; SANs localhost/keycloak/127.0.0.1 serve BOTH the host recipe
  and the docker variant), NOT a secret — the same class the test tier commits.
- The spec I/O matrix's couple observable is trued as-built in README §5.3: on a REVERSE cell
  `relay_binds_accepted_total` has no pre-registered series (no routing table; AD-19 forbids
  free-form system_id labels) — the observable is `relay_binds_unknown_total` (+ the
  `bind_accept` JSON line); the honesty note is stated in both READMEs.
- §5.5 (the ratified docker-proxy variant) is documented with its load-bearing deltas (compose
  network + service-name dials — the cert's `keycloak` SAN exists for this; `-p 2775:2775`
  re-publish; :ro secret mounts 0444 for UID 65532) and honestly labeled "documented, not
  re-proven here" — 6.2's ComposedDockerE2eTest proved the shape; T2's live proof is the host
  recipe (the ratified default).
- README section renumbering: the launch recipe inserted as §5; troubleshooting/teardown/
  deltas/findings shifted to §6–§9 in BOTH languages with all cross-references trued
  (EN normative, RU the committed translation twin).
- Gradle inertness at T2 stays structural: `git status` shows zero Gradle-file changes (only
  `.gitignore`, `sandbox/**`, and this spec file); the formal `clean build` GREEN check stays
  with T4.

T3 completion notes (2026-09-17):

- T3 executed per the one-task-per-conversational-step rule; T4 (proofs/catalog/ledger) NOT
  started — the `./gradlew clean build --console=plain` GREEN check, the catalog rows, the
  interop-note/deferred-work sweep, and the `epic-6-context.md` regeneration all stay with T4.
- Owner directive honored again: NOTHING committed, no git state mutated — no `git add`, no
  `git commit`; the working tree carries T3's edits beside the staged T2 index, untouched.
- The journeys are the A-1-plan ops-tier shape in miniature (oracle/preconditions/per-hop
  expected observations), every observation executed live on 2026-09-17's rig before it was
  written down; where a value is run-specific the README states the DELTA to observe, not the
  absolute.
- The ONE T3 code change is the `group = smsbox-route` addition to
  `sandbox/conf/smsc-kannel.conf` (9 lines incl. the comment) — a RIG fix, not a port deviation
  in spirit: the playground never routed MOs, so its conf could not serve the spec's
  `deliver_sm` journey. Surfaced by executing the journey (the `smsbox_list empty!` symptom),
  root-caused in Kannel 1.5.0's `bb_boxc.c` broadcast rule, fixed minimally, and documented as
  deltas-list item 4 in both READMEs + the compose.yml header + three troubleshooting rows. No
  proxy defect was found by any journey (nothing to bounce); the Kannel-side quirks found
  (fakesmsc's glibc double-free crash on bearerbox restart; opensmppbox answering its own
  credential refusal with the same 0x0D the AD-33 collapse uses) are README interop notes, with
  the catalog/deferred-work sweep deferred to T4 as tasked.
- The wire-observation honesty note the journeys carry: on THIS rig the AD-32-verbatim arm and
  the AD-33-collapse arm are wire-identical down to the code (opensmppbox itself answers 0x0D);
  the discriminating surfaces are opensmppbox's own PDU dump and the metric shape
  (`BIND_FAILED_NON_ROK` both legs vs `BIND_REJECTED` ingress-only) — stated in README §6.4
  rather than papered over.
- The deny journeys' procedures live entirely in conf edits + `docker compose restart`
  (`usr2`/`pwd2` for the AD-32 arm — the realm user T2 landed for exactly this; a wrong password
  for the AD-33 arm); `front-kannel.conf` verified byte-identical to HEAD after both reverts;
  each restore re-coupled within one 10 s retry.
- README §1's "the ONE wiring delta" phrasing trued to "the ONE wiring RE-POINT" with the
  MO-routing delta named beside it (both languages); §2's `smsc-kannel.conf` row and the
  compose.yml header comment carry the same truing; sections renumbered §6–§9 → §8–§11 with the
  journeys as §6 and the debugging guide as §7, all cross-references swept (§-reference audit
  run on both files).
- Gradle inertness at T3 stays structural: `git status` names no Gradle file (only
  `.gitignore`, `sandbox/**`, this spec — and now `sandbox/conf/smsc-kannel.conf`); the formal
  `clean build` GREEN check stays with T4.

T4 completion notes (2026-09-17):

- T4 executed per the one-task-per-conversational-step rule; all four story tasks are now
  complete — the story awaits its review round.
- Owner directive honored to the end: NOTHING committed across the whole story — no `git add`,
  no `git commit`; the T1–T3 staged index untouched, all T4 edits landing as unstaged
  working-tree changes beside it.
- The clean-build proof closes the claim T1–T3 each carried forward structurally: GREEN in
  3m 3s, 521 tests (0 failed, 0 skipped — the Docker suites included), zero Gradle-file
  changes, zero build-file references to `sandbox/`. The sandbox is proven inert, not assumed.
- The catalog rows follow the OBS-035/037 precedent as tasked: dated, ops-tier, labeled
  `[manual rig — Story 6.3]`, non-CI by construction (the proof artifact is the documented
  journey with per-hop expected observations, executed live 2026-09-17 per `sandbox/README.md`
  §6). The count amendment 254 → 258 follows the RELAY-027/028 and DEPLOY-015 row-additions
  precedent (tallies amended in step, dated note at the top). No P0/P1 coverage claim rides on
  the new rows (all P2) — the coverage core is untouched.
- The "ledger" half of the task is visibly DECIDED, not skipped: no proxy defect was found by
  any journey (T3's live runs — nothing to bounce to an owning epic), and the two Kannel-side
  quirks are README interop notes, the spec's terminal disposition for Kannel findings — neither
  is actionable (upstream Kannel 1.5.0 behavior; the only imaginable proxy-side changes would be
  sandbox-convenience tuning the Always rules forbid), so `deferred-work.md` gains NO 6.3 entry.
  The `smsbox-route` conf gap T3's journey surfaced was already fixed in the rig itself (T3,
  deltas item 4) — not a deferral.
- README status headers trued in both languages (T1+T2+T3 → T1–T4; the "remaining task: T4"
  line replaced by the T4 record: clean-build GREEN, the catalog rows, the epic-context
  regeneration). No T1–T3 journey/guide content was re-edited.

### File List

- `sandbox/compose.yml` — the 7-service chain (ported; +`name:`, `build: ./kannel`).
- `sandbox/kannel/Dockerfile` — Kannel 1.5.0 pinned-source build, byte-identical port.
- `sandbox/conf/front-kannel.conf` — the ONE wiring delta (2775) + trued route diagram.
- `sandbox/conf/db.conf`, `front-sqlbox.conf`, `smsc-kannel.conf`, `smsc-opensmppbox.conf`,
  `smsc-users.txt` — byte-identical ports.
- `sandbox/init.sql` — the pgsql DLR tables, byte-identical port.
- `sandbox/README.md` — the T1 bring-up guide (readiness table, failure-naming troubleshooting
  table, teardown semantics, deltas list, findings discipline) + mermaid chain schema + §2.1
  opensmppbox use case; T2/T3 append to it.
- `sandbox/README.ru.md` — Russian translation of the README (EN normative; owner addition
  2026-09-17).
- `_bmad-output/implementation-artifacts/6-3-kannel-sandbox.md` — T1 checkbox + this record.

T2 (2026-09-17) additions/changes:

- `sandbox/compose.yml` — + the `keycloak` service (pinned 26.7.0, fixture-mirrored launch,
  TCP healthcheck, 8443 published, cert/key/truststore/realm mounts) + the header comment trued
  to the 8-service rig.
- `sandbox/keycloak/realm-smpp-companions.json` — NEW: the realm export (mirrors the test-tier
  realm; DAG-on confidential client with NO embedded secret — generated at import; ROPC users
  `usr1`/`pwd1` + `usr2`/`pwd2`).
- `sandbox/keycloak/certs/{server.pem, server-key.pem, ca.pem, truststore.p12}` — NEW: the
  Keycloak TLS material, byte-identical copies of the committed test fixtures (SANs
  localhost/keycloak/127.0.0.1; truststore pw `smpp-test`).
- `sandbox/secrets/oidc-client-secret` — NEW, gitignored (AD-18): the operator-bootstrapped
  generated client secret; never committed (`.gitignore` covers the directory).
- `.gitignore` — + `sandbox/secrets/` (the AD-18 entry, commented).
- `sandbox/README.md` — + §5 "The proxy launch recipe" (5.1 Keycloak + the one-time secret
  bootstrap; 5.2 build+launch with the arg-rationale table; 5.3 the ordered expected
  observations incl. the `/metrics` honesty note; 5.4 the fails-loudly table incl. the
  live-run mutation signatures; 5.5 the optional docker-proxy variant); §1 mermaid + prose gain
  the Keycloak node/ROPC edge; §2/§3/§4 tables gain the keycloak/certs/secrets rows, the 8443
  (+9090) port rows, the keycloak readiness row, the discovery smoke line; §6–§9 renumbered
  with new troubleshooting rows (keycloak health, discovery 404, SEC-060 refusal, stale-secret
  deny) and the Keycloak teardown/regeneration semantics.
- `sandbox/README.ru.md` — the Russian twin of every T2 change above (docs/ru conventions;
  EN normative).
- `_bmad-output/implementation-artifacts/6-3-kannel-sandbox.md` — T2 checkbox + this record.

T3 (2026-09-17) additions/changes:

- `sandbox/conf/smsc-kannel.conf` — + the `group = smsbox-route` MO-routing delta (commented
  in-file): `smsbox-id = usr1`, `smsc-id = FAKE1` — required for the §6.2 deliver_sm journey
  (Kannel broadcasts MOs only to boxes without a boxc-id; opensmppbox carries one).
- `sandbox/README.md` — + §6 "The correctness journeys" (6.1 happy send + DLR round trip;
  6.2 deliver_sm injection incl. the line syntax and the tty-attach mechanics; 6.3 enquire_link
  with the keepalive-vs-pre-couple-idle-timeout note; 6.4 the two deny journeys with the
  wire/log/metric surface table) and §7 "The debugging guide — the entry points" (the 9-row
  entry-point table + the two debugging heuristics); §6–§9 renumbered to §8–§11 with all
  cross-references trued; the header status note, §1's one-delta phrasing, §2's
  `smsc-kannel.conf` row, three new troubleshooting rows, and deltas-list items 4–5 added.
- `sandbox/README.ru.md` — the Russian twin of every T3 change above (docs/ru conventions; EN
  normative).
- `sandbox/compose.yml` — the header comment's delta list trued to name the MO-routing conf
  delta (no service change).
- `_bmad-output/implementation-artifacts/6-3-kannel-sandbox.md` — T3 checkbox + this record.

T4 (2026-09-17) additions/changes:

- `_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md` — + the dated Row-additions
  note (2026-09-17, Story 6.3 T4), a §8.1 heading over E2E-001, §8.2 "The Kannel manual-rig
  journeys" with rows **E2E-002..E2E-005** (each `[manual rig — Story 6.3]` with its
  live-executed Status bullet), the §1.1/§1.2 tallies amended 254 → 258, and §9.4's A-1
  testability-boundary dated parenthetical.
- `_bmad-output/implementation-artifacts/epic-6-context.md` — regenerated to as-built: the dated
  regeneration comment, the Goal status line, the 6.3 DONE summary.
- `sandbox/README.md` + `sandbox/README.ru.md` — the status headers trued to T1–T4 (T4's record:
  the clean-build GREEN proof, the catalog rows, the epic-context regeneration); no other content
  touched.
- `_bmad-output/implementation-artifacts/6-3-kannel-sandbox.md` — T4 checkbox + this record.
