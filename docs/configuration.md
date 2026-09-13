# Configuration Reference — every live `companion.*` key

> **Status:** authored with Story 6.1 (2026-09-12) — this page is documentation only, nothing in
> the repository parses it (owner rule 2026-09-10: no Java test's oracle is a markdown page), so
> page↔reality coherence is a review-time duty: a key change goes through a story that touches
> `application.yml`, the config records, AND this page · **Audience:** operators configuring any
> role×mode cell, in either packaged shape · **Oracle:** the shipped
> `proxy/src/main/resources/application.yml` and the records under
> `proxy/src/main/java/smpp/companion/proxy/config/` (`ProxyCompanionProperties`,
> `CompanionConfigValidator`, `MemoryBudget`) — where this page and the code disagree, the code
> wins and this page is buggy.

The proxy is configured through one namespace, `companion.*`, bound by
`@ConfigurationProperties("companion")` with **`ignoreUnknownFields = false`**: every key that
exists is documented below, and a config carrying a typo'd, speculative, or
retired key **refuses startup** with a binder error naming the key (fail-closed, AD-11). Anything
an operator cannot set here cannot be set anywhere — there is no management API, no runtime
reload; the whole surface is read once at boot and is immutable afterward (AD-8).

**What this page does not cover** (each has its own home): the JVM launch flags — including the
`-XX:MaxDirectMemorySize` interlock with `companion.memory.*` — live in
[`operator-jvm-flag-contract.md`](operator-jvm-flag-contract.md); per-cell launch walkthroughs and
the `docker run` recipe live in [`deployment-guide.md`](deployment-guide.md); the JSON log events
and `/metrics` surfaces live in [`runbooks.md`](runbooks.md); the full cipher policy and its
tuning envelope live in [`cipher-allowlist-policy.md`](cipher-allowlist-policy.md). There are no
performance numbers anywhere in this documentation (Epic 7 will publish those).

## How configuration reaches the proxy

Five supply channels, in Spring Boot's precedence order (highest first):

1. **Run args** after the jar path (`--companion.reverse.mode-b.smsc.host=smsc.carrier.example`).
   In the Docker shape, arguments after the image name append to the ENTRYPOINT the same way —
   one arg channel, both shapes (see the flag-contract page).
2. **Java system properties** (`-Dcompanion.bind.port=2776`, before the jar path) — note this
   position is JVM-flag territory per the
   [flag contract](operator-jvm-flag-contract.md): anything before `-jar` must ride both
   packaged shapes or neither.
3. **OS environment variables**, relaxed-bound: dots become underscores, dashes are removed,
   everything upper-cased (`companion.bind.port` → `COMPANION_BIND_PORT`;
   `companion.reverse.mode-b.acknowledged` → `COMPANION_REVERSE_MODEB_ACKNOWLEDGED`).
   Note the AD-18 consequence: every key that carries secret *material* is a **file path** —
   `client-secret-path`, `trust-store.path`, `cert-path`, `key-path` — so no value key exists for
   an environment variable to bind (owner decision 2026-09-11, "env is accepted" as a channel:
   a secret VALUE placed in the environment is inert by construction, honored nowhere).
4. **An `application.yml` beside the jar** (`./application.yml`, `./config/application.yml`).
5. **The jar's own `application.yml`** — lowest precedence; it ships the common-key defaults
   below. Its branch templates are *commented documentation*: an uncommented branch key inside
   the jar would bind that branch for every deployment of that jar, so the shipped file never
   carries live branch keys. Consequence for operators: **every required branch key must be
   stated explicitly** in channels 1–4 — required branch keys have no defaults anywhere (the
   `oidc.timeout`/`oidc.max-in-flight` pattern: the yml template documents `4s`/`64` as the
   values to copy, but nothing supplies them for you).

Lists bind comma-separated in args/env (`--companion.tls.protocols=TLSv1.3,TLSv1.2`); routing
entries are indexed (`--companion.forward.mode-a.routing[0].system-id=carrierOne`). Durations
carry an explicit unit (`4s`, `30s`, `10s`). Every failure below is a **startup refusal**
(non-zero exit) with a message naming the offending key — the AD-17 fail-fast contract.

## The role × mode matrix (AD-17) — the cell is the property path

One instance = one role (`forward` | `reverse`) × one mode (`A` | `B` | `C`). The cell is encoded
**structurally**: populate EXACTLY ONE of the five mode-leaves
(`companion.forward.mode-a`, `companion.forward.mode-c`, `companion.reverse.mode-a`,
`companion.reverse.mode-b`, `companion.reverse.mode-c`). Zero branches refuses
("no companion.<role> branch is configured — exactly one is required (AD-17) — refusing to
start."); two refuses ("exactly one companion.<role> branch is allowed (AD-17); found 2 —
refusing to start."). Under [B] topology the **reverse** holds the internet-leg TLS listener and
the **forward dials it per SMPP session**; the SMSC leg is always plaintext/trusted.

| Cell | Listener / dial posture | Required under the branch | Structurally absent — a stray key refuses |
|---|---|---|---|
| `forward.mode-a` | trusted-leg plaintext listener; per-session **one-way TLS dial** to the reverse | `trust-store` (anchors the reverse's server cert, SEC-096), `routing` (non-empty allow-list, AD-29/SEC-058) | `oidc` (no node — the forward is a trusted-side relay; the reverse adjudicates, AD-12 amended 2026-08-18), `smsc` (not required — it dials the routing target, SEC-097), `server-cert` |
| `forward.mode-c` | trusted-leg plaintext listener; per-session **mTLS dial** | `client-cert` (per-instance, SEC-057/FR-AUTH-3), `trust-store` (SEC-050), `routing` | `oidc`, `smsc`, `server-cert` |
| `forward.mode-b` | — | — | **FORBIDDEN**: no `companion.forward.mode-b` node exists (Mode B is reverse-only; SEC-051 is structural, not a runtime check) |
| `reverse.mode-a` | internet-leg **one-way TLS** listener (presents the server cert, validates no peers) | `smsc` (SEC-059), `server-cert` (SEC-056), `oidc` (SEC-054) | `trust-store` (one-way TLS never validates peers — the accepted-risk register entry; ACL-isolate the listener via `companion.bind.host` or use Mode C), `routing`, any client material |
| `reverse.mode-b` | internet-leg **plaintext** listener; legacy clients connect directly (no forward proxy exists) | `smsc`, `acknowledged: true` (the explicit opt-in, SEC-052), `oidc` — Mode B still adjudicates ("plaintext + ROPC") | all TLS material |
| `reverse.mode-c` | internet-leg **mTLS** listener | `smsc`, `server-cert`, `trust-store` (REQUIRE-validates the forward's client cert — never WANT, AD-13/SEC-050), `oidc` | `routing`, client material (the forward presents the cert) |

`companion.forward.tls-contexts` (optional) exists only on the forward role — both forward cells —
because only the forward dials TLS (AD-29 amendment, 2026-08-26). The reverse role carries no
routing table: every bind routes to the single configured SMSC endpoint.

## Common keys — every cell, defaults shipped in `application.yml`

### `companion.bind.*` — the proxy's own SMPP listener

| Key | Type | Default | Fail-fast guard |
|---|---|---|---|
| `companion.bind.port` | int | `2775` | must be in [1, 65535] (SEC-055) |
| `companion.bind.host` | string | `0.0.0.0` | required, non-blank (F13 listener hardening) |
| `companion.bind.adjudication-deadline` | duration | `4s` | required; zero/negative refuses (compact-ctor guard) |
| `companion.bind.pre-couple-idle-timeout` | duration | `30s` | required; zero/negative refuses (compact-ctor guard) |

`bind.host` is the listener's bind address (Story 3.3, F13): `0.0.0.0` = all interfaces (the
pre-3.3 behavior); an internet-leg listener (reverse A/C, or Mode B's direct listener) SHOULD be
scoped to the interface it is reachable on.

`adjudication-deadline` is one number with **three** relay-side roles (deliberately one knob —
the F13 one-number precedent): (1) the verifier budget — `RequestContext.deadline = now + this`,
handed to the bind adjudicator (Story 2.2 T7); (2) the egress dial bound — the per-bind SMSC
connect carries `CONNECT_TIMEOUT_MILLIS` = this value, so a blackholed target fails at the
deadline, not Netty's ~30s default (Story 4.4 T1/F10); (3) the ingress deny timer — a verifier
future that never settles is denied and torn down at this budget (Story 4.4 T3/F14).

`pre-couple-idle-timeout` bounds **connect→couple only** (Story 4.4 T4): a connection that still
has not reached the couple when the window elapses is closed fail-closed (no response PDU), so an
accepted-but-never-binding socket cannot hold its `concurrent-pairs` cap slot forever. It is
cancelled at the couple — idle COUPLED pairs are never reaped. It is a separate knob from the
deadline because slot-reclaim cadence is an ops concern, not part of the auth budget; `30s` sits
well above the legitimate cold path and the 4s deadline, well below "forever".

### `companion.memory.*` — the AD-30 direct-memory budget

| Key | Type | Default | Fail-fast guard |
|---|---|---|---|
| `companion.memory.max-inbound-depth` | int | `64` | ≥ 1 (AD-30) |
| `companion.memory.concurrent-pairs` | int | `1024` | ≥ 1 (AD-30) |
| `companion.memory.safety-factor` | double | `1.5` | finite and ≥ 1.0 (AD-30; `@DecimalMin` plus an explicit Infinity refusal) |
| `companion.memory.budget-check` | enum `fail` \| `warn` | `fail` | unknown enum tokens refuse the bind; any non-`warn` value (including absent) is treated as `fail` |

Netty allocates every SMPP PDU buffer off-heap; the direct-memory cap is **derived**, not
free-standing:
`MaxDirectMemorySize = SmppFrame.MAX_COMMAND_LENGTH × max-inbound-depth × concurrent-pairs ×
safety-factor`, where the max-frame input is the codec's fixed constant 65536 (RELAY-026 — it is
deliberately NOT a config key, so the codec max and the budget cannot drift). The three tunable
inputs are the keys above. At the shipped defaults the derivation is 65536 × 64 × 1024 × 1.5 =
**6,442,450,944 bytes (6 GiB)** — exactly the `-XX:MaxDirectMemorySize` value in the
[flag contract](operator-jvm-flag-contract.md). **Interlock:** retune the trio and retune the
flag to at least the new derived budget, or the AD-30 live startup self-check
(`DirectMemoryBudgetStartupCheck`, unconditional for every cell) compares the derived budget
against the JVM's live ceiling and — under `budget-check: fail`, the default — **refuses
startup** ("AD-30 direct-memory budget … exceeds the JVM's live direct-memory ceiling — refusing
to start (AD-17/AD-30)"). `warn` is the explicit accepted-risk opt-in (the Mode B pattern): a
loud starred banner, then start. No value skips the check itself — it always computes and
compares; only the over-budget severity is tunable.

`concurrent-pairs` is also the **accepted-connection cap** (Story 3.3 review rework, 2026-08-26):
every accepted connection can become a budgeted coupled pair, so the acceptor's
`ConnectionCapHandler` reads this key directly — over-cap accepts are force-closed with a WARN.
There is deliberately no separate connection-cap knob (the retired `bind.max-connections` was
folded away as a two-knobs-one-number drift surface).

### `companion.tls.*` — the AD-34 protocol/cipher policy

| Key | Type | Default | Fail-fast guard |
|---|---|---|---|
| `companion.tls.protocols` | list of strings | `TLSv1.3`, `TLSv1.2` | non-empty, no blank entries, TLS 1.2 floor (SEC-061 — sub-1.2 names refuse), every entry JDK-supported |
| `companion.tls.tls12-cipher-suites` | list of strings | the four ECDHE/AES-GCM suites (below) | the union of both cipher lists must have a non-empty intersection with the JDK-default `SSLContext`'s supported suites (AD-34) |
| `companion.tls.tls13-cipher-suites` | list of strings | the three JDK AEAD suites (below) | same intersection guard |

The policy applies to **every TLS context both roles build** — the reverse's internet-leg
listener (A/C), the forward's per-session dial (A/C), the per-target `tls-contexts` overrides,
and the reverse's IdP client context (the ROPC token-endpoint link). TLS 1.2 minimum, 1.3
preferred; the TLS-1.2 default set is exactly
`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`,
`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (no CBC, no
static-RSA, no RC4/3DES); the TLS-1.3 default set is exactly `TLS_AES_256_GCM_SHA384`,
`TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`. Each runtime TLS context re-intersects
the configured set against that context's supported suites and refuses startup on an empty
intersection. The policy rationale and the operator-tuning envelope (what you may safely add or
remove, and what each change costs) live in
[`cipher-allowlist-policy.md`](cipher-allowlist-policy.md).

### `companion.metrics.*` — the read-only Prometheus endpoint

| Key | Type | Default | Fail-fast guard |
|---|---|---|---|
| `companion.metrics.port` | int | `9090` | must be in [1, 65535] |

The whole node is **optional**: absent (a programmatic fixture build) means the `/metrics`
endpoint stays down; the shipped default keeps production observable. The **bind address is
deliberately not a key**: the endpoint binds the literal `127.0.0.1` — loopback IPv4 is the
endpoint's sole authentication, so a non-loopback exposure cannot be misconfigured into
existence, and no Docker `-p 9090` publish finds anything listening. Scrapes are GET-only,
exact-path `/metrics`, and mutate nothing. What the scrape exposes is catalogued in
[`runbooks.md`](runbooks.md).

### `companion.shutdown.*` — the AD-22 graceful-shutdown drain

| Key | Type | Default | Fail-fast guard |
|---|---|---|---|
| `companion.shutdown.drain-timeout` | duration | `10s` | required; zero/negative refuses (compact-ctor guard) |

After the acceptor stops and in-flight adjudications deny, established pairs drain — in-flight
writes flush and peers half-close — until this budget expires; the remainder is force-closed as
`SHUTDOWN_DRAIN`, so a peer that never half-closes can never hang the exit. **Operator contract,
not validated:** keep it strictly below the 30s `spring.lifecycle.timeout-per-shutdown-phase`
ceiling the jar's yml ships — a deadline at/above the phase window would let Spring cut the walk
mid-drain.

### Adjacent shipped keys (outside `companion.*`, for completeness)

The jar's `application.yml` also ships: `spring.main.web-application-type: none` (AD-16 — the
app stays non-web even if a web starter leaks onto the classpath), `spring.main.banner-mode:
'off'` (stdout is a pure JSON-lines stream), `spring.lifecycle.timeout-per-shutdown-phase: 30s`
(the drain ceiling above). PDU bodies are TRACE-gated and OFF by default — the relay's body
logger is addressable through the standard logging keys
(`logging.level.smpp.companion.proxy.relay.pdu: TRACE`); the bind family stays redacted at every
level, so the password never crosses at any level. See [`runbooks.md`](runbooks.md) for the log
reference.

## Branch keys — exactly one branch per instance

### `companion.forward.mode-a.*` and `companion.forward.mode-c.*`

| Key | Type | Required | Fail-fast guard |
|---|---|---|---|
| `<branch>.trust-store.path` | string (file path) | yes | 5-state PKIX load — see the `TrustStore` sub-record below |
| `<branch>.trust-store.password` | string | no (nullable) | tolerated by `KeyStore.load` when absent |
| `<branch>.client-cert.cert-path` | string (file path) | mode-c only | file readable (SEC-060); PEM parseability is the TLS factory's eager bean-init load |
| `<branch>.client-cert.key-path` | string (file path) | mode-c only | file readable (SEC-060); ditto |
| `<branch>.routing[i].system-id` | string | yes, per entry | non-blank; **unique** across the table (the allow-list, AD-29 — a duplicate refuses) |
| `<branch>.routing[i].host` | string | yes, per entry | non-blank |
| `<branch>.routing[i].port` | int | yes, per entry | [1, 65535] |
| `<branch>.routing[i].tls-context-id` | string | no | if present, must reference an existing `companion.forward.tls-contexts` key — a dangling id refuses (SEC-098/AD-29) |

The routing table is a `system_id` **allow-list** mapping each permitted id to the single egress
target (AD-29: v1 is 1:1 — each entry's `host`:`port` is the reverse proxy that the forward
dials). A bind whose `system_id` is not in
the table denies fail-closed (no default route, AD-11). The table is immutable after startup.
The mode-c client cert is **per-instance** (one cert per runtime instance, FR-AUTH-3 — never a
shared golden-image key); rotation is re-deploy.

### `companion.forward.tls-contexts.*` (optional, forward role only)

A map of `id → client cert+key`: `companion.forward.tls-contexts.<id>.cert-path` and
`companion.forward.tls-contexts.<id>.key-path`, both required file paths (SEC-060). A routing
entry's `tls-context-id` selects one; an entry without it uses the instance-level default (mode-c's
own client cert; trust-only in mode-a). Forward-scoped because only the forward dials TLS under
[B] (AD-29 amendment, 2026-08-26 — the earlier top-level `companion.tls.contexts` location is
retired, see below).

### `companion.reverse.mode-a|mode-b|mode-c.*`

| Key | Type | Cells | Fail-fast guard |
|---|---|---|---|
| `<branch>.smsc.host` | string | a, b, c | required, non-blank (SEC-059) |
| `<branch>.smsc.port` | int | a, b, c | [1, 65535] |
| `<branch>.server-cert.cert-path` / `.key-path` | string (file paths) | a, c | readable files (SEC-056/SEC-060); PEM/key parseability is the TLS factory's eager bean-init load |
| `<branch>.trust-store.path` / `.password` | see `TrustStore` below | c | 5-state PKIX load — REQUIRE-side anchor (SEC-050) |
| `<branch>.acknowledged` | boolean | b | must be `true` to start — "companion.reverse.mode-b (plaintext) requires explicit opt-in (companion.reverse.mode-b.acknowledged=true) — refusing to start (SEC-052/AD-17)." |
| `<branch>.oidc.*` | see below | a, b, c | see the OIDC sub-record |

Mode B (`acknowledged: true`) starts with a loud WARN banner — the shipped text quotes
`CompanionModeBWarning` verbatim in the [deployment guide](deployment-guide.md); the accepted
risk it names is plaintext SMPP passwords on the internet leg. Mode A boots with the analogous
`CompanionModeAWarning` (one-way TLS: the reverse cannot authenticate the connecting forward —
ACL-isolate the listener or use Mode C). Both banners ride the JSON-lines stdout stream as single
WARN lines (since Story 5.1 T3).

### The `TrustStore` sub-record (every trust-store key, all cells)

`path` required, `password` optional. The store must load as a real trust store at bind time —
the 5-state PKIX refusal matrix: blank path / not-a-path / missing / directory / unreadable /
empty (zero bytes) / wrong format or wrong password / zero `trustedCertEntry` entries each refuse
startup (SEC-050, message naming the path; **PKCS12 is expected on JDK 9+ — JKS is not
supported**). The trust store **never falls back to JDK `cacerts`** (AD-13/AD-26): use a minimal
single-purpose store holding your issuing-CA roots. Trusting public PKI for a peer is an explicit
opt-in with a loud warning, never the default — the runbook entry lives in
[`runbooks.md`](runbooks.md).

### The `oidc` sub-record (every reverse cell — the sole enforcement point before the SMSC)

| Key | Type | Default | Fail-fast guard |
|---|---|---|---|
| `<branch>.oidc.provider-url` | URI | — (required) | https scheme + a host (SEC-053/054 — hostless and `http://` refuse); a non-URI string refuses at bind conversion |
| `<branch>.oidc.client-id` | string | — (required) | non-null, non-blank |
| `<branch>.oidc.client-secret-path` | string (file path) | — (required) | readable file (SEC-060/AD-18) — the sole provider client auth |
| `<branch>.oidc.trust-store.path` / `.password` | see `TrustStore` | path required | readable + loadable (AD-13: never `cacerts`) |
| `<branch>.oidc.timeout` | duration | — (required; yml template documents `4s`) | **validated**: inclusive [2s, 5s] (PERF-3) AND ≤ `companion.bind.adjudication-deadline` — out-of-window or over-deadline refuses (since Story 4.4 T5) |
| `<branch>.oidc.max-in-flight` | int | — (required; yml template documents `64`) | ≥ 1 (AD-28(4)) |

Four dated policy blocks govern this node (mirroring `application.yml`):

- **The token endpoint is derived, not discovered** (Story 3.4 T9, 2026-08-29). The proxy makes
  **no provider wire call at startup** — no discovery document is fetched, no issuer check runs.
  The token endpoint is derived as `<provider-url>/protocol/openid-connect/token`, so
  `provider-url` MUST be the **Keycloak realm base** (e.g.
  `https://idp.example.com/realms/smpp-companions`), not the provider host root; there are no
  per-endpoint override keys. A single trailing `/` is tolerated (canonicalized away).
- **JWT-only adjudication** (Story 3.4 T1, 2026-08-27). The token endpoint must issue JWT access
  tokens: a 200 response carrying a non-JWT (opaque) token denies fail-closed
  (`DenyIndeterminate` + a WARN naming the policy); there is no second-arm fallback. Remediation
  is provider-side — configure the client/realm to issue JWT access tokens (the pinned Keycloak
  ≥26.7.0 issues JWTs by default; see the deployment guide's trust disclosure).
- **TLS as the sole trust anchor** (Story 3.4 T2, 2026-08-27). No local JWT signature
  verification and no cached provider keys exist — the TLS-authenticated provider link is the
  only anchor. The former third budget key (`jwks-cache-ttl`) is retired; a config still
  carrying it refuses startup.
- **Direct Access Grants are an operator prerequisite.** ROPC (the password grant) is per-client
  and **OFF by default since Keycloak 26.2** — enable it on the client, or every bind denies
  fail-closed at **first bind** via the unchanged verdict mapping, with a starred
  `OPERATOR_WARNING` naming the derived token endpoint and the `provider-url`. The proxy makes
  no startup check for this; the first bind is where it surfaces.

`timeout` is the per-call HTTP budget for one provider round trip; `max-in-flight` is the
admission cap on **concurrent** adjudications — a bind arriving when all permits are held is
refused fail-closed (`DenyIndeterminate`) without any wire call. It is a rejection threshold,
not a queue: nothing waits. Size it comfortably above the expected concurrent bind rate so
saturation means a provider stall, not normal load. The removal-track disclosure for ROPC itself
(RFC 9700 / OAuth 2.1 status, the Keycloak build-pinning requirement) is the deployment guide's
[trust section](deployment-guide.md).

## Retired keys — and the loud refusal each now gets

`ignoreUnknownFields = false` has no grace period for history: a config still carrying any key
below **refuses startup** at bind time, and the binder's unknown-field error names the key (the
"… does not exist" family, pinned by the config-matrix tests). Each retirement was a deliberate
simplification, not a deprecation cycle — there are no transition shims and no dual-bind windows.

| Retired key | Was | Retired | As-built successor |
|---|---|---|---|
| `companion.role` | the role selector key (the branch path now selects the cell) | Story 1.3 (2026-08-04) | `companion.<role>.<mode>.*` — the cell IS the path |
| `companion.bind.max-connections` | the accepted-connection cap | Story 3.3 checkpoint rework (2026-08-26) | `companion.memory.concurrent-pairs` (one number: budget input = cap) |
| `companion.tls.contexts` | top-level per-target client-cert override map | Story 3.3 checkpoint rework (2026-08-26, AD-29 amendment) | `companion.forward.tls-contexts` (forward-scoped — only the forward dials TLS) |
| `<branch>.oidc.client-mtls-keystore` | the RFC 8705 mTLS provider-auth arm | pre-release, 2026-08-19 (Story 3.2 amendment 5) | none — `client-secret-path` is the sole provider client auth |
| `<branch>.oidc.client-credential-path` | the client-secret path key's earlier name | pre-release rename (Story 3.2) | `<branch>.oidc.client-secret-path` |
| `<branch>.oidc.jwks-cache-ttl` | the cached-JWKS TTL budget key | Story 3.4 T2 (2026-08-27) | none — no cached provider keys exist (TLS-as-sole-trust-anchor) |

If a refusal names a key you did not write, look for an env var or an external `application.yml`
layer left over from an earlier deployment — the error's key name is the path as the binder saw
it.

## Cross-references

- [`operator-jvm-flag-contract.md`](operator-jvm-flag-contract.md) — the four launch flags; the
  `-XX:MaxDirectMemorySize=6442450944` ↔ `companion.memory.*` interlock; the documented
  `spring.main.lazy-initialization` deviation (it defers this page's entire fail-fast matrix to
  first use — enabling it is an accepted deviation, owner decision 2026-09-10).
- [`deployment-guide.md`](deployment-guide.md) — per-cell walkthroughs in both packaged shapes,
  the canonical `docker run` recipe, the ROPC removal-track disclosure, the Mode A/B banners.
- [`runbooks.md`](runbooks.md) — the JSON log-event and `/metrics` references, the deny-surface
  table, shutdown/exit semantics, Mode A ACL isolation, JFR/dump hygiene.
- [`cipher-allowlist-policy.md`](cipher-allowlist-policy.md) — the full cipher policy, the
  per-context empty-intersection refusal, and the tuning envelope for `companion.tls.*`.
