---
title: 'Story 9.1 — Runbook human walkthrough (Epic 9 opener)'
type: 'chore'
created: '2026-09-30'
status: 'ready-for-dev' # draft | ready-for-dev | in-progress | in-review | done
route: 'dispatch'
review_loop_iteration: 0
context: ['{project-root}/_bmad-output/implementation-artifacts/epic-9-context.md']
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Epic 9 (the whole-codebase meaty review) opens with the operator experience: the runbooks have never been run through end-to-end by a human as a set — no systematic pass has confirmed the documented steps actually run, the instructions are clear, the log output is understandable, metrics are visible, and IDE debugging works.

**Approach:** The owner walks each in-scope runbook on the sandbox rig while this session preps each run's state, watches outputs, and records every finding in an Epic 9 findings/triage ledger with a per-point verdict — fixed now / deferred (ledgered) / declined with reason / needs more research. The root README status flips to `meaty review` at start. Findings drive fixes inside this story (walkthrough-scoped) per the owner's reviewer-decision rule.

**Owner decisions (2026-09-30):**
- **Scope:** the §5 host-run recipe once + all three `sandbox/runbooks/` use-case runbooks (reverse-mode-b, forward-reverse-mode-a, forward-reverse-mode-c), journeys §6.1–6.4 exercised along the way; §5.5 bridge variant / TRACE PDU dump / JFR arms are optional per-point decisions, not obligations.
- **README placement:** a `**Status:** meaty review` line under the intro AND the proxy + sandbox Modules-table cells flip from `**WIP**` to `meaty review`.

## Boundaries & Constraints

**Always:**
- English-only edits: `docs/`, `sandbox/`, root `README.md` — never `docs/ru/`, `README.ru.md`, or any `.ru.md` runbook twin (RU sync is the last Epic 9 story).
- The owner executes the runbook steps — the human run-through is the deliverable; the agent preps, observes, records, and fixes.
- Every finding gets an explicit triage verdict in the ledger before story close; deferred items also get a `deferred-work.md` entry when they need a future home outside this story.
- One task per conversational step; one commit per task, only on explicit owner approval.

**Never:**
- No code/test review passes (later Epic 9 stories: `code` pass, `code+tests` pass, test-group review).
- No CI/publish/pipeline changes; no performance work (Epic 7).
- No main-code/test restructuring beyond what a walkthrough finding directly demands and the owner approves in-session.
- No Russian docs sync meanwhile.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Rig bring-up (sandbox §4) | `docker compose up -d` | all 9 services healthy, §3 port plan holds | §8 bring-up troubleshooting table |
| Host-run proxy (§5) | §5.1 secret bootstrap, `bootJar` + `java -jar` (§5.2 flags) | binds couple, §5.3 observations match, logs = documented JSON events | §5.4 failure table |
| Journey §6.1–6.3 | send SMS / MO / enquire_link per runbook | expected wire + log + metric movement | deny surface maps per docs/runbooks.md |
| Deny journeys §6.4 (D1/D2) | wrong credentials / routing miss | bind_reject on wire + log + counter, exactly per the deny-surface table | N/A (this IS the error arm) |
| Metrics visibility | `curl 127.0.0.1:9090/metrics`; Prometheus `127.0.0.1:9095` | documented series present and moving; 9090 target UP | 9091 shows DOWN-with-reason until a two-instance runbook runs |
| Two-instance runbooks (mode A/C) | second instance on 2776 / metrics 9091 | 9091 target UP, both instances' series visible | §5.4 |
| IDE debugging | IntelliJ attach or run config on the host-run shape | a product-code breakpoint hits during a journey, state inspects cleanly | N/A |
| SIGTERM on host-run proxy | `kill <pid>` | exit 143, shutdown walk order per docs/runbooks.md | N/A |

</frozen-after-approval>

## Code Map

- `sandbox/README.md` — §3 prerequisites + port plan, §4 bring-up, §5 host-run recipe (§5.1 secret, §5.2 launch, §5.3 observations, §5.4 failures, §5.6 packaged runbooks), §6 journeys, §7 debugging guide, §8 troubleshooting, §9 teardown.
- `sandbox/runbooks/{reverse-mode-b,forward-reverse-mode-a,forward-reverse-mode-c}.md` — the three use-case runbooks (EN files; `.ru.md` twins exist, untouched).
- `sandbox/compose.yml` — 9 services: kannel×6, `pg`, `keycloak` (26.7.0, 8443, realm import), `prometheus` (host network, UI 9095).
- `sandbox/prometheus/prometheus.yml` — targets 127.0.0.1:9090 + 9091, 5s interval.
- `docs/runbooks.md` — deny-surface table, provider-misconfig banners, JSON log-event reference, `/metrics` reference, shutdown/exit semantics, troubleshooting table; the oracle for "log output understood".
- `docs/deployment-guide.md`, `docs/configuration.md`, `docs/operator-jvm-flag-contract.md` — consulted when a step references them; not walkthrough targets themselves.
- `README.md` — intro (~L5), Modules table L21–26 (proxy/sandbox **WIP**), "Try it" L29; status line lands near the intro. `README.ru.md` is the untouchable RU twin.
- `.idea/workspace.xml` (gitignored) — local run config `ProxyCompanionApplication`; documented IDE-attach posture is host `java -jar` (sandbox/README.md:104 — "host launch gives IDE-debugger attach"; the string is in the sandbox README, not the root README).
- `_bmad-output/implementation-artifacts/sprint-status.yaml` — append `9-1-runbook-human-walkthrough` key, flip `epic-9: backlog → in-progress`.
- `_bmad-output/implementation-artifacts/deferred-work.md` — deferral mirror; already carries two pending two-instance observations (9091 UP; 122+N scrape formula) this story can settle opportunistically.

## Tasks & Acceptance

**Execution:**
- [ ] `README.md` + `_bmad-output/implementation-artifacts/sprint-status.yaml` + new `_bmad-output/implementation-artifacts/meaty-review-findings.md` — set README status `meaty review` (intro line + proxy/sandbox Modules-table cells); append the 9-1 story key and flip epic-9 to in-progress; create the Epic 9 findings/triage ledger (per-finding: surface, observation, verdict, evidence) — story start markers.
- [ ] Host-run walkthrough (§5) — rig §4, secret §5.1, bootJar + `java -jar` §5.2, §5.3 observations, §6.1–6.4 journeys, metrics 9090 + Prometheus 9095, log reading vs `docs/runbooks.md`, IDE breakpoint confirmation, SIGTERM exit — findings ledgered with verdicts.
- [ ] `sandbox/runbooks/reverse-mode-b.md` walkthrough — packaged shape, single instance, §6 journeys per the runbook — findings ledgered.
- [ ] `sandbox/runbooks/forward-reverse-mode-a.md` walkthrough — two instances, 9091 arm; capture the two pending 8.2 observations if reached — findings ledgered.
- [ ] `sandbox/runbooks/forward-reverse-mode-c.md` walkthrough — mTLS cell, two instances — findings ledgered.
- [ ] Fix round + close — apply approved walkthrough fixes (EN docs/runbooks/config text), record deferrals, leave every finding with a verdict.

**Acceptance Criteria:**
- Given the rig is up, when the owner runs each in-scope runbook end-to-end, then every step executes as written or its failure/ambiguity is a ledgered finding with a verdict.
- Given any log line the journeys emit, when read against `docs/runbooks.md`, then each is mapped to a documented event (or ledgered as undocumented).
- Given loopback scrape and Prometheus UI, when journeys run, then the documented series are visible and move (binds, PDUs, adjudication).
- Given the host-run instance, when the IDE debugger attaches and a journey runs, then a product-code breakpoint hits and state inspects cleanly.
- Given story start, the README status reads `meaty review` — intro line plus the proxy and sandbox Modules-table cells.
- Given story close, every ledger finding carries fixed/deferred/declined-with-reason/needs-research, and `git diff` shows zero changes under `docs/ru/`, `README.ru.md`, `sandbox/README.ru.md`, and `.ru.md` runbooks.

## Implementation Notes

## Spec Change Log

## Review Triage Log

## Design Notes

Working mode (matches the owner's reviewer-decision rule): the owner executes; this session preps each run's rig state, tails logs, pulls scrapes, and writes ledger rows live. The Epic 9 ledger (`meaty-review-findings.md`) is the single findings home for ALL Epic 9 stories; `deferred-work.md` mirrors only deferrals needing a future home. Two pending 8.2 two-instance observations (9091 UP; 122+N rows) settle opportunistically in the mode A/C sessions — per-point decisions, not ACs.

No written IDE-attach recipe exists anywhere in the docs (no jdwp/agentlib references) — the AC4 vehicle is IntelliJ attach-to-process against the host-run JVM, plus the local `ProxyCompanionApplication` run config. The absence of a written recipe is itself a candidate ledger finding during the walkthrough (per-point decision).

## Verification

**Commands:**
- `git diff --stat -- docs/ru README.ru.md sandbox/README.ru.md 'sandbox/runbooks/*.ru.md'` -- expected: empty (RU untouched).
- `./gradlew clean build` -- expected: GREEN (required only if any fix touches code/config).

**Manual checks (if no CLI):**
- Ledger completeness: every finding row names surface + observation + verdict + evidence link.
