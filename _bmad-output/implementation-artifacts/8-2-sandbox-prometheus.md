---
title: 'Story 8.2 — Sandbox Prometheus'
type: 'feature'
created: '2026-09-20'
status: 'ready-for-dev'
route: 'dispatch'
review_loop_iteration: 0
context:
  - {project-root}/_bmad-output/implementation-artifacts/epic-8-context.md
  - {project-root}/_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Nothing consumes the proxy's metrics in the sandbox rig — the loopback-only `/metrics` (AD-19) is reachable only by hand (`curl` from the host shell), so the rig never demonstrates the observability story end-to-end and the Story-8.1 histogram surface has no live consumer.

**Approach:** Add a pinned Prometheus service to `sandbox/compose.yml` that scrapes the loopback endpoint via a sandbox-only network-namespace pattern — the service joins the host namespace, the namespace both supported proxy postures run in, so the target is the literal `127.0.0.1:9090` — proven live before it lands. Fixture scope per addendum A7: the product's loopback-only binding and fail-closed posture stay byte-intact.

**Owner decisions (2026-09-20):** Q1 = always-on (the service starts with the plain `docker compose up`; no compose profile). Q2 = the web UI binds loopback-only, `127.0.0.1:9095`. Q3 = BOTH static targets always configured — `127.0.0.1:9090` and `127.0.0.1:9091` — accepting that every single-instance rig shows the 9091 target DOWN until a second instance launches. Spec kept whole above the token guideline (single goal; the overage is Code Map citations).

## Boundaries & Constraints

**Always:**
- AD-19 byte-intact: nothing under `proxy/` changes; the metrics bind stays the literal loopback + `companion.metrics.port` (yml default 9090); access comes from namespace sharing, never from bind widening or port publishing.
- Fixture scope (A7; sprint-change-proposal §conflict): the Prometheus service and its web UI are rig fixtures; the product §13 "no metrics dashboard / telemetry backend / management API" non-goal stands.
- Image pinned exactly (the Keycloak 26.7.0 precedent); the new host port lands in README §3 EN+RU; EN normative, RU structural mirror with the terminology-glossary conformance sweep.
- The namespace pattern is proven live (rig up + running proxy, target UP, both histogram families flowing) BEFORE the service lands; evidence recorded in Implementation Notes.

**Never:**
- No `-p 9090`/`-p 9091`, no `ports:` entry for metrics, no `EXPOSE` change, no `networks:` key added to compose for this; no product meter/seam work (`proxy/observability/` untouched).
- No CI, `.github/`, Docker Hub, pull-based compose, deployment-guide or `docs/runbooks.md` product-doc work (Story 8.3 owns those).
- No closing of ledgered items (sandbox supply-chain hardening, the secrets `check-ignore` guard, 8.1's G3/G6/G7) — they stay ledgered.
- No auto-reformat of untouched files — hand style stands.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Default posture scrape | Rig up + host-run proxy (README §5.2), metrics on yml-default 9090 | `smpp-proxy` target UP; counters + both histogram families queryable in the UI | Scrape failures surface as `up == 0` in the UI |
| Runbook docker shape | Proxy container `--network host` (§5.6 / runbooks) | Same target UP — same (host) namespace | Same |
| Proxy not launched | Rig up, no proxy process | Target DOWN (connection refused); rig otherwise healthy | Documented in README §5.3/§5.4 |
| Two-instance runbooks | Second proxy on 9091 | Both targets always configured: the 9091 job goes UP when the second instance launches | Single-instance rigs show the 9091 target DOWN — accepted (Q3) |
| Host 9090 held by another process | Proxy boot | Proxy refuses startup (AD-17) — unchanged; target stays DOWN | Product behavior untouched |
| §5.5 bridge variant | Proxy on the compose bridge network | Loopback metrics unreachable from a host-ns Prometheus — stays a documented variant limitation | N/A |

</frozen-after-approval>

## Code Map

- `sandbox/compose.yml` -- 8 services, NO `networks:` key (implicit default only), per-service comment-block style; the Keycloak 26.7.0 pin (:137-160) is the image-pinning precedent; kannel `extra_hosts: host.docker.internal:host-gateway` reaches the host's routable interface, NOT its loopback — insufficient for `/metrics`.
- `sandbox/README.md` -- §3 port table :155-170 (compose-published vs host-must-be-free — the ledger the new port joins); §5.2 :295-315 host-run launch (metrics rides yml-default 9090); §5.5 :407-426 bridge variant (metrics structurally unreachable — limitation to state); §5.6 :441-470 docker shape + `--network host` rationale; mermaid topology :57-86.
- `sandbox/README.ru.md` -- structural §-mirror of the EN README; owner terminology glossary binds the new text.
- `sandbox/runbooks/{reverse-mode-b,forward-reverse-mode-a,forward-reverse-mode-c}.md` + `.ru.md` twins -- the docker-shape usage surface; `reverse-mode-b.md:82-99` the `--network host` run, :150-156 "Why `--network host`", :128 the hand-curl scrape; the a/c runbooks run the second instance on 9091.
- `proxy/.../observability/MetricsEndpointLifecycle.java` -- DO NOT CHANGE: literal `LOOPBACK_BIND_HOST` :77, `companion.metrics.port`, absent node = endpoint down, occupied port = AD-17 fail-fast.
- `.../prds/prd-smpp-companions-2026-07-18/addendum.md` -- A7 :75 fixture-scope ruling; A8 :79-86 the scrape-arithmetic baseline (121 forward / 120 reverse / N-id formula) this story's live check consumes.
- `_bmad-output/planning-artifacts/epics.md` :427-437 -- Epic 8 charter: the netns-join recommendation, packages owned, no new FRs.
- `_bmad-output/implementation-artifacts/deferred-work.md` -- :878-883 open sandbox supply-chain + secrets-guard entries (adjacent, stay ledgered per Never); :887-895 8.1 gaps G3/G6/G7 (owned elsewhere).
- `docs/runbooks.md` :187-272 -- product `/metrics` reference; Story 8.3 territory, untouched here.

## Tasks & Acceptance

**Execution:**
- [ ] `sandbox/compose.yml` + `sandbox/prometheus/prometheus.yml` -- add the pinned Prometheus service (`network_mode: host`; UI loopback-only on `127.0.0.1:9095` — 9090/9091 taken, 9093 is the Alertmanager convention; named TSDB volume + short retention; short scrape interval), always-on (no compose profile), with TWO static targets under the `smpp-proxy` job — `http://127.0.0.1:9090/metrics` and `http://127.0.0.1:9091/metrics`; prove the pattern live FIRST and record the evidence in Implementation Notes. -- The fixture lands only after its access pattern is proven (the proposal's named risk).
- [ ] Live conformance check vs A8 -- run the rig's journeys with real traffic, reconcile the live scrape rows against A8's baseline, append the dated first-live-check note to addendum A8. -- A8 declares itself the baseline for the next live conformance check; 8.2 is its first consumer.
- [ ] `sandbox/README.md` -- §1 topology (mermaid + prose), §2 layout table, §3 port table row, §4 bring-up (always-on — no extra command), §5.3 expected observations (UI + target states incl. DOWN-when-no-proxy and the DOWN 9091 in single-instance rigs), §10 deltas honesty list. -- The rig doc must match the rig.
- [ ] `sandbox/README.ru.md` -- mirror the T3 sections; run the terminology-glossary conformance sweep over the new text. -- RU twins stay structurally identical.
- [ ] `sandbox/runbooks/*.md` + `.ru.md` twins (3 pairs) -- one pointer each in "What you should see": the hand-curl observation gains the Prometheus UI route; the two-instance runbooks (a/c) note the always-configured 9091 target — UP only while the second instance runs, DOWN otherwise. -- The runbooks are the docker-shape usage surface.

**Acceptance Criteria:**
- Given the rig up and a host-run proxy (§5.2 defaults), when browsing the Prometheus UI on its listen address, then the `smpp-proxy` target is UP and after a journey both histogram families (`relay_binds_adjudication_seconds`, `relay_pdus_transit_seconds`) carry data.
- Given the rig up with no proxy launched, then the target reads DOWN and every other service is unaffected — stated in README §5.3.
- Given the post-journey live scrape, its row set reconciles with A8's arithmetic, or the delta is explained in the A8 dated note.
- Given `sandbox/compose.yml`, no `ports:` entry publishes 9090/9091; the story's whole diff touches nothing under `proxy/`.
- Given the RU mirror, the glossary conformance sweep passes (owner terminology; TLS/mTLS untranslated).

## Implementation Notes

## Spec Change Log

## Review Triage Log

## Design Notes

- Why `network_mode: host` IS "joins the proxy's network namespace": both supported proxy postures (host-run jar §5.2; runbook `--network host` containers §5.6) live in the host namespace, so a compose service with `network_mode: host` shares the proxy's namespace and scrapes the literal `127.0.0.1:9090` — the only in-repo precedent where an external scraper touches the loopback endpoint (runbooks' "Why `--network host`"). The §5.5 bridge variant's metrics stay in-container-only (DEPLOY-011 posture) and unreachable — documented, not fixed.
- The service needs no `ports:` mapping at all (host namespace; the UI binds directly); a `ports:` block under `network_mode: host` is silently ignored by compose and would mislead readers — omit it.
- TSDB on a named compose volume with a short retention (~24h) — dev rig, no durability promise.

## Verification

**Commands:**
- `(cd sandbox && docker compose config)` -- expected: parses; the prometheus service shows `network_mode: host` and no ports publishing
- `grep -nE '909[01]' sandbox/compose.yml` -- expected: metrics-port references appear only in comments/scrape context, never in a `ports:` publish
- `./gradlew clean build` -- expected: GREEN (nothing under `proxy/` changed; house rule: docs-only rounds still build clean)

**Manual checks (if no CLI):**
- The T1 live proof and the T2 A8 reconciliation records in Implementation Notes (commands run, observations, row counts).
