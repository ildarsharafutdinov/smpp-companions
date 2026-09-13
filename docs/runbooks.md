# Runbooks — the deny surface, the log and metrics references, shutdown, and deployer-dependent controls

> **Status:** authored with Story 6.1 T3 (2026-09-13) — this page is documentation only, nothing in
> the repository parses it (owner rule 2026-09-10: no Java test's oracle is a markdown page), so
> page↔reality coherence is a review-time duty: a behavioral change goes through a story that
> touches the code AND this page · **Audience:** operators diagnosing a live instance (or one that
> refuses to start) and the people reading its logs and metrics · **Oracle:** the as-built classes
> named inline — `MeteredRelayObserver`, `StartupSummaryLogger`, `ResourceMetrics`,
> `ObservabilityConfig`, `MetricsHttpHandler`, `MetricsEndpointLifecycle`, `RopcBindCredentialVerifier`,
> `BindInterceptor`, `RelayEgressHandler`, `ProxyCompanionLifecycle`, `CloseReason` — where this page
> and the code disagree, the code wins and this page is buggy.

The proxy is headless: no UI, no management API, no dashboard. Everything an operator can observe
arrives on exactly three surfaces — the **SMPP wire** (what the legacy client or the SMSC sees), the
**JSON log stream** (stdout), and the **`/metrics` scrape** (loopback-only). Every section below is
organized around that rule: for each outcome, it names WHERE the outcome surfaces — a row that
cannot name its surface does not belong on this page.

**What this page does not cover** (each fact has one home): the `companion.*` keys —
[`configuration.md`](configuration.md); the launch recipes, the verbatim Mode A/B boot banners, the
ROPC removal-track disclosure — [`deployment-guide.md`](deployment-guide.md); the JVM flag set —
[`operator-jvm-flag-contract.md`](operator-jvm-flag-contract.md); the TLS cipher lists and their
tuning envelope — [`cipher-allowlist-policy.md`](cipher-allowlist-policy.md). There are no
performance numbers anywhere in this documentation: where a sizing question exists, Epic 7's
performance report (Story 7.1) is where the numbers will publish.

## The deny surface — where every bind failure surfaces

Two wire contracts govern everything below, and they are deliberately different:

- **AD-33 (proxy-originated denials collapse).** Every denial the PROXY itself produces — a
  verifier `Deny*` verdict, the fail-closed verifier-failure arms, a routing miss on the forward, a
  retry-bind, the adjudication deadline, a bind arriving after the acceptor stopped, and every
  egress-establishment failure that produces no SMSC response PDU (connect refused/failed, SMSC
  death before `bind_resp`) — answers the wire with **ONE generic code**: a header-only 16-octet
  `bind_*_resp` carrying `command_status = ESME_RBINDFAIL 0x0000000D` (SMPP 3.4 §5.1.3), matching
  the request's `command_id` and `sequence_number`, followed by close. A prober cannot distinguish
  "bad password" from "unreachable SMSC" from "not routed" on the wire. The rich outcome lives
  only in the log line and the metrics.
- **AD-32 case 4 (SMSC-originated answers pass through verbatim).** A non-ROK `bind_*_resp` or a
  `generic_nack` from the SMSC is the SMSC's own answer — the SMSC is the sole credential
  authority, so its actual response bytes are forwarded to the legacy client **unchanged** (no
  couple, both legs close after). A prober CAN distinguish "reached the SMSC" from
  "proxy-rejected" — a mild credential-validity oracle accepted within the no-rate-limit risk.
  Distinct from both: a pre-couple NON-BIND PDU (`submit_sm` pipelined before `bind_resp`,
  `enquire_link`, `unbind`, an unknown `command_id`, …) gets **no response at all** — the
  connection just closes (AD-32's uniform above-spec bare-close).

| Outcome | Origin | Wire (what the client sees) | Log | Metric |
|---|---|---|---|---|
| Verifier returned `DenyInvalid` or `DenyIndeterminate` (bad credentials, provider 401/400 `invalid_grant`/`invalid_client`, 3xx/403/404/429/5xx, timeout, network error, opaque token, admission saturation) | proxy | header-only `bind_*_resp` `0x0000000D`, then close | INFO `bind_reject` line: `system_id`, `verdict` (`DenyInvalid` \| `DenyIndeterminate`), `bind_resp_command_status="0x0000000D"`; the non-credential provider arms additionally fire their WARN banners (below) — the positive-invalid signals (401, `invalid_grant`/`invalid_client`) log nothing beyond the `bind_reject` line, by design | `relay_binds_rejected_total` + (reverse cells) `relay_binds_unknown_total`; close `relay_connections_closed_total{direction="INGRESS",reason="BIND_REJECTED"}` |
| SMSC non-ROK `bind_*_resp` | SMSC | the SMSC's actual response bytes, verbatim, then close | nothing at default level (the close is observed, not logged) | close `{reason="BIND_FAILED_NON_ROK"}` on both legs |
| SMSC `generic_nack` pre-`bind_resp` | SMSC | the nack bytes, verbatim, then close | nothing at default level | close `{reason="GENERIC_NACK_PRE_BIND"}` on both legs |
| Egress-establishment failure (SMSC connect refused/blackholed/failed, SMSC death or violation before `bind_resp`) | proxy | the generic `0x0000000D` deny, then close | nothing at default level — this arm is deliberately silent (indistinguishable from a verifier deny, by design) | close `{direction="INGRESS",reason="EGRESS_CONNECT_FAILED"}` (stashed on the client leg only; where an egress leg existed and died pre-answer, that leg's own close counts under the unstashed default `{direction="EGRESS",reason="OTHER"}` — a failed connect never opened one at all) |
| Routing miss (forward cells: `system_id` not in the table) | proxy | the generic deny, then close | WARN `routing miss: system_id not in the routing table — AD-33 deny (AD-29/AD-11): <id>` | close `{direction="INGRESS",reason="OTHER"}` (no reject counter — no Verdict was returned) |
| Adjudication deadline elapsed, verifier never settled (dead/silent provider) | proxy | the generic deny, then close | WARN `adjudication deadline elapsed without a verdict — fail-closed deny (F14): <id>` | close `{direction="INGRESS",reason="BIND_REJECTED"}` (no reject counter — the timer fabricates no Verdict) |
| Bind after the acceptor stopped (shutdown in progress) | proxy | the generic deny, then close | WARN `bind after acceptor stop — fail-closed deny, no adjudication started (OBS-017): <id>` | close `{direction="INGRESS",reason="OTHER"}` |
| Retry-bind while a handshake is in flight | proxy | the generic deny answering the RETRY's sequence, then close | nothing at default level | close `{direction="INGRESS",reason="BIND_REJECTED"}` |
| Pre-couple non-bind PDU on the client leg (pipelined `submit_sm`, `enquire_link`, …) | proxy | **no PDU** — bare close | nothing at default level | close `{direction="INGRESS",reason="PRE_COUPLE_NON_BIND_PDU"}` on the violating leg |
| Pre-couple non-bind PDU on the SMSC leg (e.g. a `deliver_sm` before `bind_resp`) | proxy | the SMSC leg closes bare; the client leg then receives the generic `0x0000000D` deny (the bind died unanswered — the collapse) | nothing at default level | close `{direction="EGRESS",reason="PRE_COUPLE_NON_BIND_PDU"}` (the violating leg) + `{direction="INGRESS",reason="EGRESS_CONNECT_FAILED"}` (the collapsed client leg) |
| Connection-cap refusal — an accept beyond `companion.memory.concurrent-pairs` (F13) | proxy | **no PDU** — the just-accepted socket is closed before any bind is read | WARN `connection refused: companion.memory.concurrent-pairs=<n> is exhausted (F13 cap) — closing <peer>` | none by design (pre-bind identity is untrusted and the observer seam is bind-scoped; AD-19 cardinality) |
| Accepted socket that never binds (or a silent SMSC after the forward) — the pre-couple idle watchdog | proxy | **no PDU** — bare close at `companion.bind.pre-couple-idle-timeout` | WARN `pre-couple idle timeout elapsed …` (two variants: never-bound socket / pair still walking the handshake) | close `{direction="INGRESS",reason="PRE_COUPLE_NON_BIND_PDU"}` |
| Shutdown drain deadline expired with pairs still live | proxy (shutdown) | legs force-closed | WARN `shutdown drain deadline (<timeout>) expired — force-closed <n> live pair(s) as SHUTDOWN_DRAIN …` | close `{reason="SHUTDOWN_DRAIN"}` on both legs of every force-closed pair |

Two counting rules that surprise people reading the metrics:

- **`relay_binds_rejected_total` counts only RETURNED verdicts.** It increments exclusively inside
  the observer's `onBindReject`, which fires only for an actual `Verdict` the verifier returned
  (AD-27). The deadline deny, the routing miss, the acceptor-stop deny, retry-binds, and
  egress-establishment failures do NOT touch it — their only metric footprint is the close
  counter. A rising `BIND_REJECTED` close count with a flat `relay_binds_rejected_total` means the
  denials are NOT credential verdicts: look for the deadline or retry WARN lines.
- **`relay_binds_accepted_total{system_id}` has series only on forward cells** — pre-registered
  for exactly the routing table's ids (the bounded label universe). Every reverse cell has an
  empty routing table by construction, so every accept there increments
  `relay_binds_unknown_total` instead; on the forward, an off-table id never gets that far (the
  routing miss denies first). A burst of distinct unknown ids grows the unlabeled counter, never
  the series count — the cardinality-attack bound (AD-19).

## The provider-misconfiguration banners — `OPERATOR_WARNING` and `OPAQUE_TOKEN_WARNING`

The proxy makes **no provider wire call at startup** — the token endpoint is derived from
`provider-url` (`<provider-url>/protocol/openid-connect/token`), so a dead, typo'd, or misconfigured
provider surfaces at **first bind**, not at boot. The banners are the loud half of that posture
(`RopcBindCredentialVerifier`); each fires **once per condition**, then one-liners:

```text
************************************************************
* OIDC TOKEN CALL FAILED — THE BIND IS DENIED FAIL-CLOSED.
* A provider misconfiguration surfaces HERE, at first bind,
* not at startup (the startup OIDC discovery probe was
* removed, Story 3.4 T9, 2026-08-29; the verdict mapping is
* unchanged — this is a warning, not a refusal).
* {}
* token endpoint: {}
* provider-url:  {}
* Operator remediation: provider-url must be the Keycloak
* REALM base (the token endpoint is derived as
* <provider-url>/protocol/openid-connect/token), the
* provider must be reachable over the trusted TLS link, and
* the client must have Direct Access Grants enabled
* (per-client and OFF by default since Keycloak 26.2) —
* otherwise every bind denies fail-closed.
************************************************************
```

(One WARN JSON line, newlines escaped, like every banner on the JSON stream.) The three slots:
what happened (the per-occurrence detail), the derived token endpoint, and the configured
`provider-url`. Every LATER occurrence of the same condition logs the one-liner instead:

```text
OIDC token call failed again — <detail> — token endpoint: <endpoint>; the starred operator banner for this condition fired once above; this bind denies fail-closed (AD-11)
```

**Condition keys** (what earns a fresh banner): the transport arm keys on the failure's
`IOException` class (a dead provider is ONE condition however many binds it denies); the status
arm keys on `status:<code>` only — HTTP 400 and 404 are two conditions, each earning its own
banner, while the provider-echoed OAuth error string rides the detail line and never the key (it
is provider-controlled free text; keying on it would let a provider re-fire the banner per bind).
A token call that SUCCEEDED but issued a non-JWT (opaque) token denies under the JWT-only policy
with its own contextual warning — deliberately NOT the starred banner, whose headline would lie
(the call succeeded):

```text
the token endpoint issued a non-JWT (opaque) access token — the JWT-only adjudication policy (Story 3.4 T1/D6, 2026-08-27) denies fail-closed; operator remediation: configure the client/realm to issue JWT access tokens (token endpoint: <endpoint>; provider-url: <url>)
```

with the one-liner `the token endpoint issued a non-JWT (opaque) access token again — …` on
repeats. The adapter's OWN shutdown aborts never fire these banners (routine restarts stay quiet);
verdicts are unaffected either way — every arm above denies fail-closed.

**Diagnosis flow.** grep the log for `OPERATOR_WARNING` (the starred block) or
`OPAQUE_TOKEN_WARNING`; read the `token endpoint:` / `provider-url:` slots to identify WHICH
provider (multi-cell operators), then:

1. **`token endpoint` not what you expected** → `provider-url` is not the Keycloak REALM base.
   Fix the URL (the endpoint is derived, never discovered; there are no per-endpoint keys).
2. **Transport arm** (`the token call failed at the transport layer`) → the provider is
   unreachable from the proxy over the trusted TLS link, or the `oidc.trust-store` does not anchor
   it. Check reachability, then the store.
3. **Status arm with HTTP 400 `(OAuth error: unauthorized_client)`** → the flagship: **Direct
   Access Grants are OFF on the client.** Keycloak ships DAG per-client and disabled since 26.2 —
   enable it on the confidential client the proxy uses, or every bind denies fail-closed. (The
   ROPC removal-track disclosure and the Keycloak ≥26.7.0 build-pinning requirement live in the
   [deployment guide](deployment-guide.md).)
4. **Status arm with 401, or 400 `invalid_grant`/`invalid_client`** → not a banner case: these are
   positive invalid-credential signals (`DenyInvalid`); the credentials or the client secret are
   wrong, per-bind, by design.
5. **`OPAQUE_TOKEN_WARNING`** → the client/realm must issue JWT access tokens (remediation is
   provider-side; there is no second wire arm in the proxy).

## The JSON log-event reference

Stdout is a **pure JSON-lines stream** (the Spring banner is off; the boot banners are WARN JSON
lines, not plain text). Every line carries `@timestamp` (ISO-8601, UTC — the `Z` suffix), `level`,
`logger_name`, `message`, and the structured fields below as top-level keys; throwables render
under `stack_trace` (and never on the SMPP wire). The events an operator greps for:

| Event / line | Level | Fields | Fires |
|---|---|---|---|
| `startup_summary` | INFO | `event`, `role` (`forward`\|`reverse`), `mode` (`a`\|`b`\|`c`), `smpp_bind_host`, `smpp_bind_port`, `metrics_port` (omitted iff the node is absent — the endpoint is down), `routing_system_ids` (sorted; empty on reverse cells), `tls_protocols`, `memory_budget_bytes`, `direct_memory_ceiling_bytes`, `max_inbound_depth`, `concurrent_pairs`, `safety_factor` | once per successful boot, on the Spring ready event — by then every fail-fast check and every listener has passed; this line IS the readiness signal |
| `bind_accept` | INFO | `event`, `system_id`, `outcome="coupled"` | at each AD-25 couple (the decoded ROK `bind_resp`), before the data plane arms |
| `bind_reject` | INFO | `event`, `system_id`, `verdict` (`DenyInvalid`\|`DenyIndeterminate`), `bind_resp_command_status="0x0000000D"` | for every RETURNED `Deny*` verdict, just before the deny is synthesized |
| the WARN catalog | WARN | free-text messages (below) | the banners above; `routing miss: …`; `adjudication deadline elapsed …`; `pre-couple idle timeout elapsed …`; `bind after acceptor stop …`; `connection refused: companion.memory.concurrent-pairs=<n> is exhausted (F13 cap) — closing <peer>`; `shutdown drain deadline (<timeout>) expired — force-closed <n> live pair(s) as SHUTDOWN_DRAIN …`; the AD-30 over-budget accepted-risk banner (only under `companion.memory.budget-check=warn`) |

High-frequency events log NOTHING — relayed PDUs and leg closes are metrics-only by design; a
per-PDU log line is exactly the flood the privacy contract keeps out of default-level logs.

**TRACE-gated PDU bodies.** Relayed PDU bodies can be logged for a debugging session — one line
per relayed PDU on the dedicated logger `smpp.companion.proxy.relay.pdu`:

```
logging.level.smpp.companion.proxy.relay.pdu=TRACE
```

(standard `logging.level.*`, any supply channel; OFF by default). The line carries the direction,
the raw `command_id` (hex), the framed length, and a full hex dump of the frame. **The bind family
is redacted at every level** — a stray post-couple re-bind logs `body=<redacted: bind family>` —
so the SMPP password never crosses into the log at ANY level. The relay's handlers observe the
`system_id` only, never a password or credential object; secret VALUES are never logged anywhere
(secret file PATHS appear in startup-refusal messages naming the offending key — the path is not
the secret, AD-18).

## The `/metrics` reference

A read-only Prometheus text endpoint on its own one-thread event loop (`companion-metrics` — a
scrape never competes with relay traffic). The contract:

- **Bind address is the literal `127.0.0.1` — there is no host key.** Loopback IPv4 is the
  endpoint's sole authentication; a non-loopback exposure cannot be misconfigured into existence.
  The only key is `companion.metrics.port` (default `9090`; an absent node leaves the endpoint
  down — see [configuration.md](configuration.md)). A port collision refuses startup (the
  standard AD-17 fail-fast).
- **GET, exact path `/metrics`** → `200`, `text/plain; version=0.0.4`. Any other method → `405`
  with `Allow: GET`; any other path (query strings included) → `404`; malformed/oversized requests
  (caps: 1 KiB request line, 8 KiB headers, 8 KiB body) → 4xx, connection closed, never a stack
  trace on the wire.
- **Scrapes are idempotent** — a scrape reads the registry and mutates nothing, not even a scrape
  counter. One scrape per connection (`Connection: close`).
- **In the Docker shape the endpoint is in-container-only BY STRUCTURE** — the image declares no
  exposed metrics port and no `-p 9090` publish finds anything listening. Scrape from inside:
  `docker cp` a compiled scrape helper (any small `java.base`-only HTTP-GET main class) into the
  running container and run it under the image's own java:

```console
$ docker cp scrape-helper.jar smpp-proxy:/tmp/
$ docker exec smpp-proxy /opt/jre/bin/java -cp /tmp/scrape-helper.jar <HelperMain> 9090
```

  (the image has no shell and no curl; the packaged-shape tests scrape through exactly this
  `docker exec`-of-the-image's-java pattern). In the JAR shape, `curl http://127.0.0.1:9090/metrics`
  on the host where the process runs.

### What the scrape exposes

**The relay counters** (all pre-registered at startup from closed label sets — no fire path can
create a series; there is no `command_id` label, no channel label, no free-form `system_id`):

| Metric | Kind | Labels | Meaning |
|---|---|---|---|
| `relay_pdus_total` | counter | `direction` ∈ `INGRESS`\|`EGRESS` | framed PDUs relayed across coupled pairs, per leg. Post-couple only: the bind handshake (the verbatim forward, the deny synthesis, the `generic_nack` forward) is uncounted by design |
| `relay_binds_accepted_total` | counter | `system_id` (pre-registered for the forward cell's routing-table ids ONLY) | binds whose ROK couple completed |
| `relay_binds_rejected_total` | counter | — (unlabeled; the verdict type is log-only — AD-33 collapses both `Deny*` verdicts to one wire status, a verdict label would fan a closed 3-value set for no operator value) | binds denied by a RETURNED `Deny*` verdict |
| `relay_binds_unknown_total` | counter | — | bind events whose `system_id` is outside the routing table (on reverse cells: every accept and every reject) |
| `relay_connections_closed_total` | counter | `direction` × `reason` (the full 2×16 grid) | legs closed, by close path |

The `reason` domain is the closed sixteen-value `CloseReason` set. **Ten fire today**:
`PEER_HALF_CLOSE`, `PEER_RST`, `EGRESS_CONNECT_FAILED`, `DECODE_ERROR` (the framer's over/undersize
rejects surface here too), `PRE_COUPLE_NON_BIND_PDU`, `GENERIC_NACK_PRE_BIND`, `BIND_REJECTED`,
`BIND_FAILED_NON_ROK`, `SHUTDOWN_DRAIN`, `OTHER` (the bounded catch-all — never a silent drop).
**Six are reserved** (registered, zero for the lifetime of the current taxonomy):
`OVERSIZED_FRAME`, `UNDERSIZED_FRAME`, `UNKNOWN_COMMAND_ID`, `CLEAN_UNBIND_HANDSHAKE`,
`INGRESS_TLS_HANDSHAKE_FAILED`, `EGRESS_TLS_HANDSHAKE_FAILED` — handshake failures currently
classify as `PEER_RST`/`DECODE_ERROR`.

**The resource gauges:**

| Metric | Kind | Meaning |
|---|---|---|
| `relay_direct_memory_used_bytes` | gauge | direct memory in use by the shared relay pooled allocator, read live off its own allocator metric — the RUNTIME answer to "is the data plane eating the arena", distinct from the once-at-boot `memory_budget_bytes`/`direct_memory_ceiling_bytes` comparison on the `startup_summary` line |
| `ropc_adjudications_active` | gauge | in-flight ROPC bind adjudications (the `ropc-adjudication` virtual-thread pool's own count — Micrometer's `jvm_threads_*` cannot see virtual threads). Present on reverse cells only; absent on a forward cell is truthful (no pool exists there) |

**The JVM binder families** (the standard Micrometer set, bound on the one registry): heap and
non-heap pools (`jvm_memory_used/committed/max_bytes` + buffer pools), GC
(`jvm_gc_live/max_data_size_bytes`, `jvm_gc_memory_allocated_bytes_total`,
`jvm_gc_cpu_time`; `jvm_gc_memory_promoted_bytes_total` exists only on generational collectors —
absent under the contract's ZGC), thread gauges (`jvm_threads_live/daemon/peak/states/started` —
platform threads only), processor (`system_cpu_count`, `system_cpu_usage`, `process_cpu_usage`,
`system_load_average_1m`), and liveness (`process_uptime_seconds`, `process_start_time_seconds`).
Two timer families are created **lazily on the first GC notification**: `jvm_gc_pause` and
`jvm_gc_concurrent_phase_time` (the latter exists at all only on concurrent collectors) — an
idle-boot scrape legitimately shows neither. `ClassLoaderMetrics` and `FileDescriptorMetrics` are
deliberately unbound.

## Shutdown and exit semantics (AD-22)

`SIGTERM` (`kill -TERM`, `docker stop`) drives a bounded graceful walk. Spring stops lifecycle
phases high-to-low, so the order is:

1. **The relay acceptor closes** (no new TCP connects). The new-adjudication gate arms: a bind
   arriving on an already-established socket from here on denies fail-closed with the generic
   status and the `bind after acceptor stop` WARN — no adjudication starts during shutdown.
2. **In-flight adjudications are denied** (`shutdownNow()` on the verifier's pool): every
   cancelled adjudication settles `DenyIndeterminate` and its continuation runs on the still-live
   relay loop — the client gets the fail-closed `bind_resp` answer, nothing strands mid-handshake.
3. **The metrics endpoint stops** — deliberately late: scrapes stay served through steps 1–2, so a
   final scrape still sees the close counters the shutdown itself produces.
4. **The coordinator walk** (the app phase, last): deny re-fire (a backstop — normally a no-op
   after step 2) → **drain**: established pairs keep relaying while the registry empties (peers
   half-close naturally) until `companion.shutdown.drain-timeout` (default `10s`) expires; the
   remainder is force-closed as `SHUTDOWN_DRAIN` on both legs with one bounded WARN naming the
   count — a peer that never half-closes can never hang the exit → **release**: a bounded await on
   the verifier pool (`oidc.timeout + 1s`), then the shared provider client closes and the
   client-secret is zeroized → **quiesce**: the shared relay loop shuts down with an explicit short
   window (100 ms quiet / 2 s cap) plus a hard 3 s termination bound — a wedged loop task gets one
   WARN and the walk proceeds anyway.

At the yml-documented `oidc.timeout` of `4s` the walk's worst case is 10 s (drain) + 5 s
(release: `oidc.timeout` + 1 s) + 3 s (quiesce bound) = 18 s; the validated ceiling of the
`oidc.timeout` window (`5s`, PERF-3) makes the absolute worst case 19 s — both inside the 30 s
`spring.lifecycle.timeout-per-shutdown-phase` ceiling the jar ships. The operator contract (not
validated — see [configuration.md](configuration.md)): keep `drain-timeout` strictly below that
30 s ceiling.

**Exit codes:**

| Code | Meaning |
|---|---|
| `143` | SIGTERM (`kill -TERM`) or `docker stop` with the walk completed — the JVM convention for a hook-completed graceful shutdown. The expected stop outcome. |
| `130` | SIGINT (`Ctrl+C` in the foreground) — the same graceful walk runs; the JVM convention 128+2. Not a crash. |
| `1` | A startup refusal (every fail-fast in [configuration.md](configuration.md)) or a boot crash — nothing partial survives: nearly all refusals fire at validation, before any listener binds, and the few lifecycle-phase failures (e.g. a metrics port collision) stop what had started on the way out. |
| `137` | SIGKILL — `kill -9`, `docker kill`, a container OOM kill (see the Docker memory-cap rule in the [deployment guide](deployment-guide.md)), or a `docker stop` whose timeout expired before the walk finished (use `--timeout 30`; the guide explains why). |

## Mode A ACL isolation — the two-proxy deployer controls (SEC-065/OBS-034)

In `reverse.mode-a` the internet leg is one-way TLS: the listener PRESENTS its server certificate
and validates no peers — the connecting forward is an unauthenticated TLS client. The residual,
accepted and registered: any peer that can REACH the listener can SUBMIT binds. It is a submission
oracle, not a harvest point — the reverse still adjudicates every submitted credential via ROPC and
the SMSC remains the sole credential authority, so a fake forward harvests nothing — but credential
GUESSES can be driven through the ROPC screen (the same no-rate-limit family as Mode B). Every
mode-a boot says so in the `CompanionModeAWarning` banner (verbatim text in the
[deployment guide](deployment-guide.md)). **The remediation is the banner's own line:**

- **ACL-isolate the listener** — scope `companion.bind.host` to the interface reachable from your
  forward-proxy hosts, and enforce network ACLs so only those hosts connect. Mirrors the
  trusted-zone confinement the whole ingress posture assumes.
- **Or run Mode C** — the mTLS listener `clientAuth(REQUIRE)`s the forward's per-instance client
  certificate against the branch trust store (never WANT): a client presenting no or an untrusted
  certificate never completes TLS (AD-13).

Two adjacent trust-anchoring controls ride the same deployer duty (OBS-034's second half):

- **Trust stores never fall back to JDK `cacerts`** (AD-13/AD-26) — on ANY path (the forward's
  reverse-anchoring store, reverse mode-c's REQUIRE store, the IdP store). The path is required,
  the store must load, and zero trusted entries refuses startup. Use a minimal single-purpose
  store holding your issuing-CA roots. **Trusting public PKI for a peer is an explicit opt-in**:
  there is no switch — the opt-in IS importing the public roots you accept into that dedicated
  store yourself — and it is loud by scope: from then on, ANY certificate chaining to those roots
  is trusted on that path. Do it knowingly, per path, never wholesale.
- **The proxy has no local brute-force or rate-limit protection** (an acknowledged, registered
  gap) — and a trusted-network attacker can drive the IdP's ROPC rate up through it. Operator-side
  IdP rate-limiting / Keycloak brute-force protection is REQUIRED, not optional hardening.

## JFR and heap-dump hygiene (SEC-049)

The credential-hygiene posture in code: bind passwords live as byte-array copies taken out of the
frame and are zeroized when the adjudication settles and at every teardown; the ROPC form and the
token-response bodies are registered per adjudication and zeroized on every completion path; the
client secret is zeroized at shutdown; and the password never enters the log at any level (the
TRACE redaction above). But **sampling profilers and heap dumps sit outside that discipline**:

- **JFR `OldObjectSample` is interval-sampled** — a short-lived per-bind credential can be sampled
  before its wipe. Absence of a sample proves nothing (this is why the test tier treats JFR/dump
  inspection as a best-effort hygiene guard, with the deterministic zeroize probes carried by the
  suites, not by sampling).
- **A heap dump captures whatever is live at dump time** — including any credential buffer whose
  adjudication had not yet settled. `OutOfMemoryError`-triggered dumps on a box relaying
  credential traffic are exactly that case.

Production guidance: keep JFR off on the proxy box unless actively diagnosing (and stop
recordings when done); prefer raising `-XX:OldObjectSampleInterval` over lowering it if you must
record; do not enable `-XX:+HeapDumpOnOutOfMemoryError` on a credential-path deployment — or, if
you must, treat the dump directory as secret-bearing (restricted permissions, encrypted or
access-controlled storage, never shipped off-host uncontrolled). Any such JVM flag addition is
flag-contract territory: it must ride BOTH deploy shapes or neither
([operator-jvm-flag-contract.md](operator-jvm-flag-contract.md)).

## Troubleshooting entries

Each row names where the symptom surfaces. Startup refusals (exit 1) are catalogued key-by-key in
[configuration.md](configuration.md); the rows below are the runtime ones.

| Symptom | Surfaces | Cause → fix |
|---|---|---|
| Every bind denies from the first one after deploy | wire `0x0000000D` + the starred `OPERATOR_WARNING` banner + `OPERATOR_WARNING_REPEAT` one-liners + `bind_reject{verdict="DenyIndeterminate"}` lines | provider misconfiguration — walk the diagnosis flow above (DAG off / `provider-url` not the realm base / provider unreachable) |
| Binds deny, no starred banner, `OPAQUE_TOKEN_WARNING` in the log | log only + wire `0x0000000D` | the client/realm issues opaque tokens → configure JWT access tokens |
| Some credentials bind, others deny with `verdict="DenyInvalid"` | `bind_reject` log lines + `relay_binds_rejected_total` | genuinely wrong credentials (provider 401 / `invalid_grant`) — not a proxy fault |
| A known client's binds all deny on a FORWARD cell | wire `0x0000000D` + WARN `routing miss: …` + close `{reason="OTHER"}` | `system_id` not in the routing table → add the entry (re-deploy; the table is immutable after startup) |
| Binds deny ~4 s after submit with no provider contact | WARN `adjudication deadline elapsed …` + close `{reason="BIND_REJECTED"}` (reject counter FLAT) | the verifier future never settled — dead/silent provider → provider-side |
| Binds deny instantly after an SMSC outage | close `{reason="EGRESS_CONNECT_FAILED"}` on INGRESS (silent otherwise — by design) | the egress dial failed or the SMSC died pre-`bind_resp` → check `smsc.host/port` (or the routing target) and SMSC reachability |
| Client connections drop right after connect, before `bind_resp` | wire: bare close (no PDU) + close `{reason="PRE_COUPLE_NON_BIND_PDU"}` | the ESME pipelines non-bind PDUs before `bind_resp` (AD-32's uniform close — no carve-outs) → the carrier must not pipeline; keepalive intervals must exceed bind latency |
| Connections that never bind close after 30 s | WARN `pre-couple idle timeout …` + close `{reason="PRE_COUPLE_NON_BIND_PDU"}` | accepted-but-never-binding sockets reaped at `companion.bind.pre-couple-idle-timeout` → expected; investigate the client if unexpected |
| Connects refused at high concurrency, no PDUs exchanged | WARN `connection refused: companion.memory.concurrent-pairs=<n> is exhausted (F13 cap)` (no wire PDU, no metric) | the accepted-connection cap (= the AD-30 budget input) is exhausted → raise `companion.memory.concurrent-pairs` AND retune `-XX:MaxDirectMemorySize` to the new derived budget, or the boot refuses |
| `-p 9090` scrape finds nothing (Docker) | no listener on the published port | by design — the endpoint binds the container's literal loopback → scrape in-container via `docker exec` (above) |
| `docker stop` exits 137, not 143 | container exit code | the stop wait expired before the walk finished → `docker stop --timeout 30` (the deployment guide's recipe) |
| Boot refuses: "AD-30 direct-memory budget … exceeds the JVM's live direct-memory ceiling" | stdout: the refusal text + exit 1 (no listener bound) | the `companion.memory.*` trio and `-XX:MaxDirectMemorySize` drifted apart → retune the flag to at least the new derived budget (flag contract) |
| Boot refuses: "… empty intersection …" (`SEC-100/AD-34`) | stdout: the refusal text + exit 1 | the configured cipher/protocol lists intersect nothing the JDK supports (or apply to none of the selected protocols) → see [cipher-allowlist-policy.md](cipher-allowlist-policy.md) |
| Scrape shows no `jvm_gc_pause` / `jvm_gc_concurrent_phase_time` | `/metrics` | normal on an idle boot — these timer families are created lazily on the first GC; force a cycle or wait |

## Cross-references

- [`configuration.md`](configuration.md) — every `companion.*` key with type/default/guard; the
  startup-refusal catalogue; the retired keys.
- [`deployment-guide.md`](deployment-guide.md) — per-cell walkthroughs in both packaged shapes,
  the canonical `docker run` recipe, the ROPC removal-track disclosure, the verbatim Mode A/B
  boot banners.
- [`operator-jvm-flag-contract.md`](operator-jvm-flag-contract.md) — the four launch flags, the
  `MaxDirectMemorySize` ↔ `companion.memory.*` interlock, the one-set rule any added flag (JFR
  tuning included) must follow.
- [`cipher-allowlist-policy.md`](cipher-allowlist-policy.md) — the cipher allowlist, the
  per-context empty-intersection refusal, and the tuning envelope for `companion.tls.*`.
