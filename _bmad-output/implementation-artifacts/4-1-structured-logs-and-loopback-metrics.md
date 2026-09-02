---
title: 'Story 4.1 — Production observability: structured JSON-lines logs and read-only loopback /metrics'
type: 'feature'
created: '2026-09-02'
status: 'in-progress'
review_loop_iteration: 0
baseline_commit: 09858836722f33e2cac06015d9ae63244fc1ad53
context:
  - /home/ildar/Documents/smpp-bmad/_bmad-output/implementation-artifacts/epic-4-context.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The proxy is operable only by grepping plain-text WARNs — no `/metrics` endpoint, no structured logging, zero INFO call sites, and Epic 2's noop `RelayObserver` seam has never been swapped for a production implementation.

**Approach:** Deliver Epic 4's observability core in `proxy/observability/`: a Micrometer-backed `RelayObserver` (DI swap, interface unchanged), a hardened read-only Prometheus `/metrics` endpoint on a dedicated Netty event loop (loopback IPv4, GET-only), JSON-lines logging (startup summary, bind accept/reject, TRACE-gated PDU bodies), plus the observer-seam hardening that must land with it: throw isolation at the four fire sites, the `BIND_REJECTED`/`EGRESS_CONNECT_FAILED` close-reason hoist, and operator-warning flood bounding.

## Boundaries & Constraints

**Always:**
- `RelayObserver` stays byte-identical (4 methods, shape-test-pinned). The production impl displaces the noop via Spring wiring; the noop file stays `final @Component`.
- `/metrics`: literal `127.0.0.1` in code (no host config key — misconfiguration impossible); GET-only, path exactly `/metrics`; other methods 405, other paths 404; bounded header/body limits; scrape mutates nothing. Netty `HttpServerCodec`+`HttpObjectAggregator` on a dedicated `companion-metrics-*` event loop, never the shared relay loop; own `SmartLifecycle` phase (stops after the acceptor, before the app phase).
- Cardinality bounded by construction: `system_id` labels only for routing-table values (pre-registered at startup from `RoutingTable`); unknown/rejected ids hit unlabeled counters; no channel-id or `command_id` labels; close counter labeled only `{direction, reason}` over the closed enum.
- Privacy: PDU bodies TRACE-only (off by default, standard `logging.level.*`); the bind password never appears at any level; startup/config summary carries no secret values.
- JSON-lines: one object per line, UTC ISO-8601 timestamps, via `logstash-logback-encoder`; tests keep a plain-console `logback-test.xml` so `OutputCapture` assertions still match.
- Throw isolation at all four fire sites: observer throwing `Throwable` → bounded WARN, relay path continues (frame forwarded/released, deny synthesis and teardown proceed, close stays exactly-once). Isolation lives at the fire sites, protecting any future impl — not only inside the production observer.
- `relay/` edits limited to the enumerated seam sites (throw wrappers, reason stash hoist, TRACE body log); `security/` edits limited to warning bounding and the VT-gauge seam.
- House rules: no `@DefaultValue` (defaults in `application.yml`); `ignoreUnknownFields=false` — every new `companion.*` key lands in `ProxyCompanionProperties` with compact-ctor fail-fast guards.

**Ask First:**
- Either new dependency (`netty-codec-http`, `logstash-logback-encoder`) requires editing the `smpp.runtime-purity` allowlist or fails a gate → HALT and show the proposed gate diff.
- Throw isolation cannot stay local to the four fire sites (needs structural relay changes) → HALT.
- The VT gauge needs restructuring of the adjudication pool in `security/` → HALT with options.

**Never:**
- No Actuator, spring-web, WebFlux, Tomcat, or any web stack (OBS-013 hard-bans).
- No management/control surface — no query/drain/reload/rotate endpoints; `/metrics` is read-only telemetry.
- No AD-22 drain body or acceptor-stop re-authoring (story 4.2); no relay-timeout round (story 4.3); no formal throughput-while-scraped proof (Epic 6).
- No metrics emission from `codec/`; the four seeded contract types stay Netty-free (ArchUnit rule stays truthful).
- `command_id` never emitted to logs/metrics outside TRACE gating, never via a codec helper.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Scrape | GET `/metrics` on 127.0.0.1:port | 200, Prometheus text (`scrape()`), idempotent, no state change | N/A |
| Wrong method | POST/PUT/DELETE `/metrics` | 405, connection closed, nothing mutated | bounded WARN at debug level |
| Wrong path | GET `/metrics/foo`, GET `/` | 404 | same |
| Oversized request | headers/body beyond limits | 4xx (e.g. 413), connection closed | no OOM, no stack trace on wire |
| Cardinality attack | burst of binds with distinct unknown `system_id`s | labeled series count unchanged; unlabeled unknown counter increments | N/A |
| Throwing observer | test double throws from each of the 4 methods | relay invariants hold: PDU forwarded, deny synthesized, pair torn down, close exactly-once | one WARN per swallowed throw |
| Bind accept | ROK couple completes | JSON INFO line: `system_id`, event, outcome | N/A |
| Bind reject | verifier returns `Deny*` | JSON line: `system_id`, verdict type, synthesized wire `bind_resp` status | N/A |
| Provider misconfig flood | dead/typo'd provider, N denied binds | full starred banner once per condition; one-liner WARN per bind | bounded |
| TRACE off (default) | relayed traffic | no PDU bodies in logs | N/A |
| TRACE on | post-couple PDUs relay | bodies logged; bind password never (bind family bypasses the site) | N/A |
| Shutdown | context close | metrics loop stops within its phase timeout; port released; later scrape refused | N/A |

</frozen-after-approval>

## Code Map

- `proxy/src/main/java/smpp/companion/proxy/observability/RelayObserver.java:28-67` — the unchanged 4-method seam; `onFramedPdu` javadoc (:31-32) claims "pre- or post-couple" but no pre-couple fire site exists (handshake forwards bypass it).
- `observability/NoopRelayObserver.java:15` — final `@Component` noop to displace (file stays).
- `observability/CloseReason.java` — closed enum, shape-test-pinned; only 7 values fire today; `BIND_REJECTED`/`EGRESS_CONNECT_FAILED` never (deny/connect-fail close as `OTHER`).
- Fire sites: `relay/CoupledRelayHandler.java:160` (`onFramedPdu`, before peer write; TRACE body log goes here — post-couple only) and `:275` (`fireClosedExactlyOnce`, CAS `CLOSE_FIRED`, from `channelInactive` :238); `relay/RelayEgressHandler.java:70` (`onBindAccept` after couple CAS, before re-arm+forward); `relay/BindInterceptor.java:370` (`onBindReject` → frame release :372 → `denyAndTeardown` :373 → `synthesizeBindFailure` :414 — the worst throw hazard).
- Stash sites for the hoist: `BindInterceptor.java:474-481` (connect-fail, no stash) and the deny paths (:277-283, :373, EgressLeg collapse ~:601/:616).
- `security/Verdict.java:19-29` — sealed `Allow`/`DenyInvalid`/`DenyIndeterminate`, zero-component records.
- `config/RoutingTable.java:27-63` — forward-only index; `entries.keySet()` is the bounded label universe (reverse cells: empty by construction).
- `config/ProxyCompanionProperties.java:43` — `companion` props, `ignoreUnknownFields=false`, no observability keys yet; no-`@DefaultValue` rule (:447-449); `Bind` compact-ctor (:382-389) is the guard pattern.
- `relay/netty/RelayNettyConfig.java:41-69` — shared `PooledByteBufAllocator` bean (direct-memory gauge source via `metric()`) + `companion-relay` loop group.
- `relay/netty/RelayServerLifecycle.java:64-119` — acceptor phase `APP_PHASE+1000`; `stop()` closes acceptor then quiesces the shared loop (NOT re-authored here — 4.2).
- `bootstrap/ProxyCompanionLifecycle.java:23` — `APP_PHASE=0`; `security/AdjudicationLifecycle.java:28` — also phase 0.
- `security/RopcBindCredentialVerifier.java:246-247` — `ropc-adjudication-N` VT pool (gauge target); `OPERATOR_WARNING` :166-183 fired at :361-363 and :420-423; sibling one-liner :462-464.
- `proxy/build.gradle.kts:22-33` — `micrometer-registry-prometheus` (:29) already present; `netty-codec-http` ABSENT (io.netty group passes the purity gate; version free via netty-bom :25). Purity gate: `buildSrc/src/main/kotlin/smpp.runtime-purity.gradle.kts:24-38`, wired into `check` (:68).
- Logging today: zero INFO sites; WARN-only `@Slf4j`; `System.err` banners `config/CompanionModeAWarning.java:45`, `CompanionModeBWarning.java:47`; no logback XML, no `logging.*` keys; tests assert via `OutputCaptureExtension` (`config/CompanionConfigMatrixTest.java:28,51`).
- Test boot: `config/TestCompanionConfigs.java:152-184` (`common()` — needs a metrics freePort); `bootstrap/BootstrapLifecycleTest.java:37-43`; `relay/netty/RelayServerLifecycleTest.java:227-233`; `observability/CapturingRelayObserver.java` (add a throwing variant); `observability/ObservabilityLayerRulesTest.java:29-38` (ArchUnit Netty-ban, FQN-scoped to the four seeded types).
- `proxy/src/main/resources/application.yml:14-16` — `spring.lifecycle.timeout-per-shutdown-phase: 30s`.

## Tasks & Acceptance

**Execution:**

*Restructured 2026-09-02 (user-directed): tasks T1–T6 are the execution units — each is implemented as a whole in one conversational step and lands as a single git commit. The former flat task list survives as per-task checkpoints (numbering preserved: checkpoint N = former task N; within a task, listed in original flat order). Each task is compile-atomic and lands build-green; T1–T6 order is the execution order.*

- **T1 — substrate** *(done — checkpoints 1-4)*
  - [x] checkpoint 1: `proxy/build.gradle.kts` -- add `io.netty:netty-codec-http` (netty-bom version) and `net.logstash.logback:logstash-logback-encoder` (explicit pin; not BOM-managed) -- endpoint handler + JSON encoder; must pass OBS-013/SEC-099 gates unchanged (Ask First if not).
  - [x] checkpoint 2: `proxy/src/main/resources/logback-spring.xml` -- JSON-lines console appender (UTC ISO-8601), root INFO -- FR-OBS-2 log shape.
  - [x] checkpoint 3: `proxy/src/test/resources/logback-test.xml` -- plain-text console for tests -- keeps `OutputCapture` substring assertions intact (logback-test.xml takes classpath precedence).
  - [x] checkpoint 4: `proxy/src/main/java/smpp/companion/proxy/config/ProxyCompanionProperties.java` + `proxy/src/main/resources/application.yml` -- optional `Metrics` component (`port`, compact-ctor 1-65535 guard; no host key) + yml default `companion.metrics.port: 9090` + `banner-mode: 'off'` -- `ignoreUnknownFields=false` demands the record node; loopback stays a code literal; stdout stays pure JSON-lines.
- **T2 — metrics endpoint slice** *(done — checkpoints 5-7, 17-18)*
  - [x] checkpoint 5: `proxy/src/main/java/smpp/companion/proxy/observability/MetricsEndpointLifecycle.java` -- NEW: `SmartLifecycle` (explicit phase between acceptor and app) owning a dedicated 1-thread `companion-metrics` loop + `HttpServerCodec`/`HttpObjectAggregator` pipeline bound to `127.0.0.1:port`; `shutdownGracefully` with explicit short quiet period -- dedicated-loop isolation (AD-19/AD-28).
  - [x] checkpoint 6: `proxy/src/main/java/smpp/companion/proxy/observability/MetricsHttpHandler.java` -- NEW: GET-only exact-`/metrics` → `PrometheusMeterRegistry.scrape()`; 405/404 otherwise; bounded content/header limits; never mutates state -- hardened endpoint contract.
  - [x] checkpoint 7: `proxy/src/main/java/smpp/companion/proxy/observability/ObservabilityConfig.java` -- NEW: `@Configuration` declaring the `PrometheusMeterRegistry` `@Bean` -- actuator is purity-banned, so its auto-configuration is absent and nothing else provides the registry.
  - [x] checkpoint 17: `proxy/src/test/java/smpp/companion/proxy/config/TestCompanionConfigs.java` -- `common()` adds `companion.metrics.port=<freePort>` -- collision-free parallel test boots (rides here so every runner test is port-safe the moment the endpoint exists).
  - [x] checkpoint 18: `proxy/src/test/java/smpp/companion/proxy/observability/MetricsEndpointTest.java` -- NEW: matrix rows 1-4 + shutdown row: 200/format, 405, 404, limits, idempotence, literal-127.0.0.1 pin, stop→refused -- endpoint contract.
- **T3 — observer, gauges, startup line** *(done — checkpoints 8-10, 19, 22)*
  - [x] checkpoint 8: `proxy/src/main/java/smpp/companion/proxy/observability/MeteredRelayObserver.java` -- NEW: `@Primary @Component` Micrometer impl — post-couple PDU counter; bind-accept counters pre-registered per `RoutingTable` id; unlabeled reject + unknown-id counters; close counter `{direction, reason}`; also logs the bind accept/reject JSON lines (`system_id`, verdict type, AD-33 synthesized wire status — SystemId is contract-reserved for exactly this); internally catch-guarded so it never throws -- the production observer (one counter source, AD-27).
  - [x] checkpoint 9: `proxy/src/main/java/smpp/companion/proxy/observability/ResourceMetrics.java` -- NEW: direct-memory gauge off the shared allocator's `ByteBufAllocatorMetric` + active-VT gauge for the `ropc-adjudication` pool (wrap submitted tasks with an inc/dec gauge — Ask First if that needs `security/` restructuring) -- memory + VT visibility.
  - [x] checkpoint 10: `proxy/src/main/java/smpp/companion/proxy/observability/StartupSummaryLogger.java` -- NEW: on ready-event, one INFO JSON line: role/mode, ports, routing-table ids, TLS mode, memory budget — no secrets -- the startup/config-resolved log line.
  - [x] checkpoint 19: `proxy/src/test/java/smpp/companion/proxy/observability/MeteredRelayObserverTest.java` -- NEW: cardinality attack row (burst of unknown ids → series count stable, unlabeled counter grows) -- PRIV-1 proof.
  - [x] checkpoint 22: `proxy/src/test/java/smpp/companion/proxy/observability/ResourceMetricsTest.java` -- NEW: both gauges present and sane -- gauge proof.
- **T4 — relay seam hardening** *(the only `relay/`-touching task — one review lens)*
  - [ ] checkpoint 11: `proxy/src/main/java/smpp/companion/proxy/relay/CoupledRelayHandler.java` -- wrap `onFramedPdu` (:160) and `onConnectionClosed` (:275) in catch-Throwable→WARN-continue; TRACE-gated body log at `relayFramedPdu` -- throw isolation + TRACE bodies (post-couple site only ⇒ password never crosses).
  - [ ] checkpoint 12: `proxy/src/main/java/smpp/companion/proxy/relay/RelayEgressHandler.java` -- wrap `onBindAccept` (:70) likewise -- throw isolation.
  - [ ] checkpoint 13: `proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java` -- wrap `onBindReject` (:370); stash `BIND_REJECTED` before the deny teardowns and `EGRESS_CONNECT_FAILED` at connect-fail (:474-481, plus the EgressLeg collapse sites) -- throw isolation + close-reason hoist so the close counter sees real reasons, not `OTHER`.
  - [ ] checkpoint 14: `proxy/src/main/java/smpp/companion/proxy/observability/RelayObserver.java` -- amend `onFramedPdu` javadoc to post-couple-only truth (no fire-site change; three pinned relay tests unaffected) -- contract honesty.
  - [ ] checkpoint 15: `proxy/src/main/java/smpp/companion/proxy/observability/CloseReason.java` -- javadoc: which values fire post-hoist; enum values unchanged (shape test pins) -- taxonomy documentation.
  - [ ] checkpoint 20: `proxy/src/test/java/smpp/companion/proxy/observability/ThrowingObserverHardeningTest.java` -- NEW: throwing double per method → relay invariants hold + WARN logged (reuse relay harness fixtures) -- seam hardening proof.
- **T5 — operator-warning bounding**
  - [ ] checkpoint 16: `proxy/src/main/java/smpp/companion/proxy/security/RopcBindCredentialVerifier.java` -- bound `OPERATOR_WARNING` (full banner once per condition + one-liner per occurrence); align the opaque-token WARN (:462-464) to the same pattern -- flood bounding under a dead provider.
  - [ ] checkpoint 24: `proxy/src/test/java/smpp/companion/proxy/security/RopcBindCredentialVerifierTest.java` -- banner-once + one-liner-per-bind assertions (OutputCapture) -- flood bounding proof.
- **T6 — log shape, rules, config guards**
  - [ ] checkpoint 21: `proxy/src/test/java/smpp/companion/proxy/observability/StructuredLogTest.java` -- NEW: every stdout line parses as JSON, ISO-8601 UTC stamps, startup line secret-free, accept/reject fields, TRACE gating + password never -- FR-OBS-2 proof.
  - [ ] checkpoint 23: `proxy/src/test/java/smpp/companion/proxy/observability/ObservabilityLayerRulesTest.java` -- keep the four-type Netty-ban rule as-is; add a rule that `MeteredRelayObserver` (and any future observer impl) stays Netty-free, with the endpoint handler explicitly exempted -- rule covers the real boundary: observers never touch Netty, the endpoint does.
  - [ ] checkpoint 25: `proxy/src/test/java/smpp/companion/proxy/config/CompanionConfigMatrixTest.java` -- guard cases: out-of-range `companion.metrics.port` fails fast -- fail-fast coverage for the new key.

**Acceptance Criteria:**
- Given a booted forward cell with routing table {alpha, beta}, when scraping, then every `system_id`-labeled series draws only from {alpha, beta} and a burst of unknown ids adds zero series.
- Given a throwing observer on any of the four methods, when a full bind→relay→unbind cycle runs, then couple, deny synthesis, teardown, and exactly-once close all behave as with the noop and each throw produced exactly one WARN.
- Given default configuration, when the app boots and serves traffic, then stdout is parseable JSON-lines with UTC ISO-8601 stamps containing no secret values and no PDU bodies; given TRACE on the PDU logger, bodies appear but never a bind password.
- Given `check` (OBS-013 + SEC-099), when the build runs with both new dependencies, then it is GREEN with no purity-gate edits.
- Given context close, when the metrics lifecycle stops, then its port is released, the shared relay loop is unaffected, and a later scrape is refused.

## Spec Change Log

## Design Notes

- **Bean displacement:** `@Primary` on the production observer — deterministic under component scanning; `@ConditionalOnMissingBean` is bean-order-sensitive. The noop remains compiled and is the fallback in minimal test contexts that exclude the metrics bean.
- **Loopback by construction:** no host key exists; the literal `127.0.0.1` is asserted by test. Simpler and more fail-closed than a validator.
- **Phase plan:** acceptor (1000) stops first, metrics (~500) next, app (0) last — scrapes stay live late in shutdown; the metrics loop never shares `companion-relay-*` threads (thread-name-pinned in tests).
- **Throw isolation at the fire sites** (not just in the impl): the seam must protect any future implementation; unhandled, a throwing `onBindReject` leaks the pooled frame, skips AD-33 deny synthesis, and hangs the client until TCP timeout.
- **TRACE bodies at `relayFramedPdu` only:** the bind family (which carries the password) bypasses this site verbatim, so the password cannot cross at any level.
- **Encoder dependency:** `logstash-logback-encoder` is not BOM-managed — pin an explicit current version; it rides logback-classic already brought by `spring-boot-starter`.

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN (all tests + OBS-013 purity + SEC-099 floors). `clean` is required — source-scan tests silently skip on incremental runs.
- `./gradlew :proxy:test --tests 'smpp.companion.proxy.observability.*' --console=plain` -- expected: all observability suites pass.

**Manual checks (if no CLI):**
- Boot a forward-A fixture; `curl -v http://127.0.0.1:9090/metrics` (200, Prometheus text), `curl -X POST` (405), `curl /metrics/x` (404); observe JSON lines on stdout and confirm no secret fields.
