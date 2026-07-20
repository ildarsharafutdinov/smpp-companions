---
review: adversarial (one-level-down divergence)
target: ARCHITECTURE-SPINE.md (Companions v1, status: draft)
reviewer: adversarial
created: 2026-07-19
method: Construct pairs of units ONE LEVEL DOWN (epics / stories) that each obey every AD to the letter and still build incompatibly. Every pair ⇒ a hole to close with a NEW or TIGHTENED AD.
---

# Adversarial Review — Companions v1 Architecture Spine

## Verdict

**FAIL — the spine is not yet a build substrate.** The big bets are right (event-loop paradigm, codec/proxy seam, ROPC + JWKS, PKIX-defaults mTLS, no native-image). But at the seams two independently-spawned epics would each be fully AD-compliant and produce artifacts that do not fit together. Four of those seams (F-1 flip/teardown, F-2 verifier contract, F-3 role×mode matrix, F-4 intra-proxy ownership) are first-sprint blockers — the relay, security, and config epics cannot even be scoped against the spine as written. The spine must be tightened (or gain the new ADs below) before any epic is split off it.

The spine also carries one **internal** contradiction that any reviewer will catch: the paradigm diagram (line 59) shows the control-plane `BindAdjudicator` flipping the splice flag (`BA -->|verdict → flip flag → splice| EL`), while AD-2 (line 74) says a data-plane `RelayHandler` flips it. Two flippers named in the same document.

## How to read each finding

Every finding names **two (sometimes three) concrete epics** one level down, the **gap** that lets them both be AD-compliant yet incompatible, and the **AD that closes it** (NEW or TIGHTENED). Severity reflects whether the seam is on the first-sprint critical path.

Findings are ranked most-severe first.

---

## F-1 [CRITICAL] — AD-2 names two flag-flippers and is silent on post-couple `unbind` handling

**The spine contradicts itself on who flips the flag, and is silent on what happens to `unbind` once the codec is dormant. Both gaps are first-sprint blockers for the relay epic.**

### The two units

- **E-RELAY-SPLICE — "RelayHandler flip + framed-ByteBuf forward."** Implements AD-2's `RelayHandler always present flips post-couple`. To know *when* to flip it reads the `bind_*_resp` command_id from the framed `ByteBuf` coming back from the egress leg (a 4-byte slice, only at the transition — it argues this is not the "per-PDU parsing on the hot path" AD-1 *Prevents*). It flips on observing any `bind_*_resp` frame. Post-flip it forwards framed `ByteBuf`s without `fireChannelRead`. For `unbind`, since the codec is dormant post-flip, E-RELAY-SPLICE treats `unbind`/`unbind_resp`/TCP-FIN all the same — teardown via `channelInactive`, never inspected.
- **E-SECURITY-BIND — "BindInterceptor session lifecycle + verdict handoff."** Implements the bind-family handling AD-3 mandates. To do its job it must (a) trigger adjudication on the ingress `bind_*`, (b) forward the bind to egress, (c) *tear the session down on `unbind(+resp)`*. To observe `bind_*_resp` it relies on the **decoded** object from `SmppCodec` (status code intact), and it signals the flip **only on `bind_*_resp` with `command_status == ESME_ROK`**. For `unbind` post-couple it keeps a lightweight post-flip detector alive so `unbind(+resp)` is still answered in-band per AD-3 / FR-TRANSIT-1.

### The gap

Both units obey AD-2 and AD-3 literally:

- AD-2 says "a `RelayHandler` always present flips post-couple" — E-RELAY-SPLICE owns the flip. The paradigm diagram (line 59) says `BindAdjudicator → flip flag → splice` — E-SECURITY-BIND's adjudicator owns the flip. **The spine names both.** Neither AD nor the diagram fixes the canonical flipper or the trigger condition.
- AD-2 says post-couple `SmppCodec` is "bypassed/dormant." AD-3 says the proxy inspects/handles `unbind(+resp)`. Post-flip the codec is dormant, so nothing decodes `unbind` — yet AD-3 still mandates it be handled. Each unit resolves this differently (RelayHandler treats it as opaque TCP teardown; BindInterceptor keeps a post-flip detector).

**Incompatibility, concretely:** on a `bind_transceiver_resp` with a non-zero `command_status` (e.g., `ESME_RINVSYSTYP`), E-RELAY-SPLICE flips (it saw a resp frame) and starts splicing; E-SECURITY-BIND does not flip (status ≠ OK) and tears down. A real carrier SMSC that returns a non-ROK `bind_resp` and then keeps the socket open produces opposite relay behavior depending on which team shipped last. Same divergence on `unbind`: in-band `unbind_resp` answered on one build, silent FIN on the other. Both teams pass every AD.

### Closing AD

**NEW AD-25 — "Bind→splice transition: single flipper, decoded trigger, post-couple teardown path."**

1. The flag flip is owned by **exactly one unit**: the data-plane `RelayHandler`. The control-plane `BindAdjudicator` NEVER mutates a data-plane flag; it returns a verdict to the `BindInterceptor`, which (still pre-flip, codec live) writes the forwarded bind and, on receipt of the decoded `bind_*_resp` with `command_status == ESME_ROK`, sets the flag on the ingress channel's event loop via `ctx.executor().execute(...)`. (Reconciles the line-59 diagram with AD-2.)
2. The flip trigger is **decoded bind_*_resp with status ROK only** — never a peeked command_id, never "any frame from egress." Pre-flip, `SmppCodec` stays live on both legs.
3. **Post-couple teardown path is fixed explicitly:** `unbind`/`unbind_resp` on a coupled channel are treated as **opaque framed bytes** and forwarded like any other PDU; the session ends on TCP half/close (`channelInactive`) on either leg, which tears the per-bind pair (AD-8). AD-3's "inspect/handle `unbind(+resp)`" applies **only on the pre-couple / standalone (single-side adoption) leg**, not to a coupled relay channel. (Or, if in-band `unbind_resp` is required, name the single post-flip detector and forbid RelayHandler peeking — pick one.)

---

## F-2 [CRITICAL] — AD-12's `BindCredentialVerifier` port has no signature, no owning package, and no canonical role

**The port is named but its contract is undefined. The security epic and the relay epic will each define a different `BindCredentialVerifier` and neither will fit the other. Separately, the spine never says which role (ingress vs egress) actually calls it.**

### The two (really three) units

- **E-SECURITY-OIDC — "BindCredentialVerifier port + ROPC adapter + JWKS verification," in `security/`.** Defines the port as a synchronous, security-package-typed interface: `VerifierVerdict verify(BindCredential cred)` returning an enum `{ALLOW, DENY}`. The input `BindCredential` is a security-package record. The ROPC adapter implements it.
- **E-RELAY-BIND — "BindInterceptor + control-plane handoff," in `relay/`.** Needs to call the verifier from `BindInterceptor`. Because the call must run off the event loop (AD-1, AD-4), it expects an **async** signature returning `CompletableFuture<Verdict>` and taking a `ScopedValue<RequestContext>` (AD-5). To call E-SECURITY-OIDC's port it would have to construct a `BindCredential` — a security-package type — i.e. a `relay → security` sub-package dependency.

And, orthogonally:

- **E-SECURITY-OIDC-INGRESS** vs **E-SECURITY-OIDC-EGRESS** — two role-scoped stories that each read AD-12's "re-validate **every** bind" differently. Ingress-only validating (egress trusts the ingress role via the internet-leg TLS) vs egress-only validating (ingress is unauthenticated by AD-15, so the egress role nearest the SMSC must be the verifier) vs both validating (literal "every"). All three are conformant readings of AD-12.

### The gap

AD-12 fixes *that* every verdict flows through a pluggable `BindCredentialVerifier` port and *that* the ROPC adapter is swappable. It fixes nothing else:

- **Signature**: sync vs async; input shape (`BindCredential` vs primitives vs codec's `BindTransceiver`); output shape (enum vs sealed verdict with reason; whether reason is exposed for metrics).
- **Owning package**: `security/` (line 287 names it there) or `relay/` (the consumer) — the source tree lists it under `security/`, but the consumer is in `relay/`. The sub-package dependency direction within `companions-proxy` is unconstrained by AD-7 (which only governs `codec ↔ proxy`).
- **Executor**: AD-4/AD-5/AD-6 say the call runs off the event loop on virtual threads, but don't say which VT pool (the relay's hand-managed pool? a security-package pool?).
- **Role**: which of ingress/egress actually calls it (see above).
- **Verdict cardinality**: AD-19 allows `system_id` tags; whether reject-reason tags are also allowed is open (F-12 folded in).

**Incompatibility, concretely:** two `BindCredentialVerifier` interfaces exist after the first sprint (security's sync `verify(BindCredential)` and relay's async `verify(BindRequest, ScopedValue)`); neither adapter fits the other; BindInterceptor can't be wired. Independently, an operator deploying the two-proxy topology gets OIDC verification on whichever role the build picked — and the *other* role silently trusts whatever arrives on the internet leg, defeating the fail-closed invariant (AD-11) on the unverified role.

### Closing AD

**TIGHTEN AD-12 — fix the port contract end-to-end.**

1. **Owning package**: `io.companions.proxy.security.BindCredentialVerifier` is the single interface. `relay` consumes it via Spring DI; `relay → security` is the only sub-package edge permitted. The reverse edge is forbidden.
2. **Signature** (fixed, verbatim): `CompletableFuture<Verdict> verify(BindCredential cred, ScopedValue<RequestContext> ctx);` where `BindCredential(SystemId systemId, char[] password)` lives in `security` (`char[]`, never `String` — wipe after use) and `Verdict` is the sealed type below.
3. **Verdict shape** (cardinality-bounded for AD-19): `sealed interface Verdict permits Allow, DenyInvalid, DenyIndeterminate {}` — exactly three values; **no Throwable, no free-form reason, no Nimbus type** crosses the port. The ROPC adapter absorbs Nimbus internally.
4. **Executor**: the verifier runs on the relay's hand-managed VT pool (AD-6 model 2), injected; never `@Async`/Spring-managed.
5. **Canonical role**: OIDC verification is performed on the **ingress role only**. The egress role trusts the ingress role's verdict via the internet-leg TLS (Mode A/C) or refuses to start in Mode B (Mode B egress would re-validate; declare explicitly). State which mode/role combinations are valid and which refuse at startup (ties into F-3).

---

## F-3 [CRITICAL] — AD-17 lists config checks flat; not projected onto a (role × mode) matrix. AD-13's trust-store rule is scoped only to Mode C, leaving Mode A egress with no defined trust store

**Two teams splitting ingress-role config from egress-role config will each apply "the validation rules" to different fields and arrive at incompatible startup contracts. Mode A on the egress role is undefined.**

### The two units

- **E-CONFIG-ROLE-INGRESS — "Ingress-role config + routing table + TLS server material."** Reads AD-17's checklist and applies: routing table required (it's an ingress concern); egress SMSC endpoint not required on ingress (ingress talks to P2, not the SMSC); Mode A → server cert+key on the internet leg (TLS server); Mode C → trust store for client certs (AD-13); Mode B → opt-in ack.
- **E-CONFIG-ROLE-EGRESS — "Egress-role config + SMSC endpoint + TLS client material."** Reads the same checklist and applies: egress SMSC endpoint required; routing table not required on egress (defensive: refuse if present?); Mode C → client cert+key + trust store for P1; **Mode A → ???** — to dial P1 as a TLS client it must validate P1's server cert somehow. AD-17 only names "trust store" under Mode C. AD-13's "trust store never `cacerts`" is titled "Mode C mTLS" and reads as Mode-C-scoped. So Mode A egress either (a) relies on the JDK default (`cacerts`) — forbidden by AD-13's spirit but not its letter — or (b) requires an operator trust store for P1 that AD-17 never mentions.

### The gap

AD-17 enumerates validation rules as a flat list and applies the cert-material clause only to modes ("A: server cert+key on the internet leg; C: client cert+key + trust store") without saying **which role** each clause is for. Several clauses are role-scoped ("ingress routing table", "egress SMSC endpoint") but AD-17 doesn't say "skip on the other role." AD-13 is titled "Mode C mTLS" so its trust-store-never-`cacerts` rule is ambiguous for non-Mode-C peer-cert validation.

**Incompatibility, concretely:**

- An ingress-only deployment (single-side adoption, explicitly supported by §8) fails E-CONFIG-ROLE-EGRESS's "egress SMSC endpoint required" check; an egress-only deployment fails E-CONFIG-ROLE-INGRESS's "routing table required" check.
- A Mode A egress-role instance either starts with `cacerts` as the trust source for P1 (silent trust-root collapse — exactly what AD-13 exists to prevent) or refuses to start because no operator trust store was provided that AD-17 never told the operator to mount. Same config, opposite outcomes.
- Mode A ingress needs a server cert+key. Mode A egress needs a client trust store (for P1's server cert). The single clause "A: server cert+key on the internet leg" describes only one of the two roles.

### Closing AD

**TIGHTEN AD-17 — publish the explicit 2 × 3 (role × mode) required-config matrix.** For each of `{ingress, egress} × {A, B, C}` name every config field as **required | optional | forbidden**:

- cert files, key files, trust store, OIDC provider URL, routing table, SMSC endpoint, Mode-B ack, etc.
- Declare role-scope of each rule ("routing table: required on ingress, forbidden on egress"; "SMSC endpoint: required on egress, forbidden on ingress").

**BROADEN AD-13** (or add **AD-26 — "Trust-store source for every peer-auth path"**) to state: *the trust-store-never-`cacerts` rule applies to **every** peer-certificate validation path, not only Mode C — including Mode A egress validating P1's server cert, and including any future TLS-client path.* Mode A egress is required to mount an operator trust store for P1 (or to set `endpointIdentificationAlgorithm` explicitly per AD-20 and pin a trust anchor); starting with `cacerts` as the peer trust source is fail-fast refuse.

---

## F-4 [HIGH] — AD-7 fixes the codec/proxy seam but is silent on intra-`proxy` ownership: the bind-family command_id set and the splice-path PDU-count metric each have two natural owners

**AD-7 only governs `companions-codec ↔ companions-proxy`. Inside `companions-proxy`, the source tree (lines 285–290) names sub-packages but no AD fixes which sub-package owns the shared enumerations and observability seams.**

### The two units (pair A — bind-family set)

- **E-CODEC-BIND-FAMILY — "Codec bind-family framing," in `companions-codec`.** Per AD-7 ("codec + PDU model + bind-family framing") owns the bind-family command_id enumeration. It has to decide whether `outbind` (SMSC→ESME, 0x0000000B) and `generic_nack` are bind-family. It excludes both (outbind isn't on the legacy ingress leg; `generic_nack` is a generic error). Non-bind PDUs pass through as `ByteBuf` (no decode), keeping the codec pure.
- **E-RELAY-BIND-INTERCEPTOR — "BindInterceptor dispatch," in `relay/`.** Needs the same enumeration. To avoid an `import io.companions.codec.*` instanceof cascade for every PDU, it redefines a local `Set<Integer> BIND_FAMILY` so it can map `generic_nack` responding to a malformed bind into the right reject counter. The two sets silently drift.

### The two units (pair B — splice metric)

- **E-OBSERVABILITY-METRICS — "/metrics scrape + counters," in `observability/`.** Per AD-19 + the memlog ("framed chunks enable free PDU-count metrics without content inspection"), wants a per-direction framed-PDU counter. Defines a `RelayMetrics` interface in `observability/` and expects the relay to call it.
- **E-RELAY-SPLICE — "RelayHandler framed-ByteBuf forward," in `relay/`.** Per AD-6 ("relay … hand-managed, not delegated to Spring") and AD-4 (no work on the event loop), refuses to let `observability` inject a hook into the hot path; instead it owns its own `LongAdder` and exposes it via a relay-package accessor. The `/metrics` handler now has two places to read from.

### The gap

AD-7 is silent on intra-`proxy` ownership. AD-19 allows `system_id` tags and a PDU count but doesn't say which sub-package emits the count. AD-3's "bind family" is never enumerated as a single source of truth.

**Incompatibility, concretely:** pair A — the codec and the interceptor disagree on whether `generic_nack`/`outbind` are bind-family; on the egress role an SMSC-sent `outbind` is decoded on one build and spliced on the other, and a `generic_nack` answering a malformed bind is mapped to a reject counter on one build and silently dropped on the other. Pair B — the `/metrics` exposition either double-counts (both the observability hook and the relay's own counter fire) or under-counts (the scrape reads one, the relay emits to the other); either way the published PERF numbers (SM-3) are wrong.

### Closing AD

**NEW AD-27 — "Intra-`proxy` ownership seams."**

1. **Bind-family command_id set** is OWNED by `companions-codec` as a single source of truth (`SmppCommandIds.BIND_FAMILY: Set<Integer>`, plus explicit `OUTBIND`, `GENERIC_NACK` declared opaque). `BindInterceptor` (`relay/`) MUST consume that set; redefining it locally is forbidden. (`outbind` and `generic_nack` are declared **opaque-spliced, not bind-family** — settles the ambiguity explicitly.)
2. **Splice-path observability seam**: a `SpliceObserver` interface is OWNED by `observability/` (methods: `onFramedPdu(Direction)`, `onBindAccept(SystemId)`, `onBindReject(SystemId, Verdict)`, `onByteTransfer(Direction, long)` — no PDU type, no content). `RelayHandler` (`relay/`) holds an injected `SpliceObserver` reference and calls it; the codec NEVER emits metrics. Cardinatity is bounded by the fixed method list + `system_id` tag (AD-19). One counter source; the Micrometer implementation is the only thing behind the seam.

---

## F-5 [HIGH] — AD-4's "bounded delegating `Executor`" and the JWKS-refresh executor are unassigned across AD-6's three models

**AD-6 says three threading models "coexist by separation" and that "relay/adjudication threading is hand-managed, not delegated to Spring." AD-4 mandates a delegating executor for `SslHandler`. AD-5/AD-6 leave the JWKS refresh executor's model unspecified. Two teams pick different models for the same executor.**

### The two units

- **E-SECURITY-TLS — "TLS modes + `SslHandler` wiring," in `security/`.** Per AD-4 builds `SslHandler` with a bounded delegating `Executor`. Reads AD-6 model 3 ("Spring-managed executors (incidental)") as permission to expose it as a Spring `ThreadPoolTaskExecutor` bean so it can be sized via `application.yml`. (Also: model 2 would let it be `Executors.newVirtualThreadPerTaskExecutor()` — virtual threads delegating SSLEngine tasks.)
- **E-RELAY-ACCEPT — "Acceptor + event-loop wiring," in `relay/`.** Reads AD-6's "relay … hand-managed, not delegated to Spring" as forbidding any Spring-managed executor on the relay path (which includes the `SslHandler` delegated-task executor — those tasks run for handshake on the relay's own channels). Builds its own platform-thread pool and refuses the Spring bean. And separately:
- **E-SECURITY-OIDC — "JWKS refresh," in `security/`.** Needs a periodic refresh task. Reads AD-5/AD-6 (control plane on stable JDK 25 primitives, hand-managed VTs) as mandating a hand-rolled VT with a `ScheduledExecutorService`. The Spring side reads AD-16 ("Spring Boot owns … lifecycle") as permitting `@Scheduled` with `spring.threads.virtual.enabled=true` (model 3).

### The gap

AD-4 fixes *that* the delegating executor exists and is bounded; it does not fix *whose* executor or *what kind*. AD-6's "incidental" for model 3 and "hand-managed" for model 2 are both defensible for an executor that sits on the data-plane accept path. AD-5 constrains only the *control* plane.

**Incompatibility, concretely:** two bounded delegating executors exist (security's Spring bean and relay's hand-rolled) and the `SslHandler` is built twice depending on which epic wired the acceptor; or virtual threads are used for SSLEngine delegated tasks and a `synchronized` block inside the JDK SSLEngine pins a carrier during an accept-storm (JDK 25 still has residual pinning points), violating AD-4's *Prevents* clause. JWKS refresh runs on `@Scheduled` on one build and a hand-rolled VT on the other; on shutdown, AD-22's "VT control-plane drain" only drains one of them.

### Closing AD

**NEW AD-28 — "Bounded delegating executors are hand-managed, single, shared, platform-thread."**

1. The `SslHandler` delegating-task `Executor` is ONE hand-managed fixed platform-thread pool (NOT virtual threads — SSLEngine delegated tasks are CPU-bound and may pin carriers; NOT a Spring `ThreadPoolTaskExecutor`). Shared by ingress + egress. Bounded queue; `RejectedExecutionException` fails the handshake → fail-closed (AD-11).
2. JWKS refresh is a hand-rolled VT on a `ScheduledExecutorService` owned by `security/` (AD-6 model 2), NOT `@Scheduled`; it is registered with the bootstrap graceful-drain (AD-22) so SIGTERM stops refresh before the JWKS cache is torn down.
3. `spring.threads.virtual.enabled` (AD-6 model 3) is permitted ONLY for Spring's own internal executors; no load-bearing path may depend on it. State this explicitly so the "incidental" wording in AD-6 cannot be read as a license.

---

## F-6 [HIGH] — AD-8 fixes the three mutable buckets but not the *home* or *shape* of per-bind state. AD-22 needs to enumerate the coupled-channel set but nothing says a registry exists

**AD-8 + AD-2 let per-bind coupling state live anywhere; AD-22's graceful drain requires enumerating it. Two teams put it in different places.**

### The two units

- **E-RELAY-COUPLING — "Channel-pair coupling," in `relay/`.** Per AD-8 stores per-bind coupling state as Netty `ChannelAttributeKey<PeerChannel>` on each channel (the `Channel.attr(...)` IS the per-bind state; gone on `channelInactive`). Minimal, no central structure.
- **E-BOOTSTRAP-LIFECYCLE — "Graceful drain," in `bootstrap/`.** Per AD-22 must "drain in-flight splices up to a configured timeout (the coupled channel set)." Needs to enumerate the coupled channels. Expects a `ConnectionRegistry` bean. E-RELAY-COUPLING scattered the state across Channel attributes; there is no registry; the drain step cannot find the channels.

And, orthogonally, the JWKS cache shape:

- **E-SECURITY-OIDC** implements the JWKS cache as a `volatile KeyList` reference swapped atomically on refresh.
- **E-BOOTSTRAP-LIFECYCLE** reads the Accepted-Risk Register ("ongoing splices survive on cached JWKS/trust") and, on SIGTERM, calls a `jwksCache.stop()` method that doesn't exist on a bare `volatile` reference.

### The gap

AD-8 enumerates the three mutable buckets but does not fix (a) the data structure that holds per-bind state, (b) whether there is a single registry or per-Channel attributes, (c) the JWKS cache's lifecycle surface.

**Incompatibility, concretely:** graceful drain either enumerates nothing (silent in-flight drop on shutdown — REL-3 violation) or has to be re-architected around a registry post-hoc. JWKS shutdown either leaks a refresh thread or races the volatile swap with a tear-down.

### Closing AD

**TIGHTEN AD-8 — fix the shape and home of mutable state.**

1. **Per-bind state home**: a single concurrent `ConnectionRegistry` bean (the source of truth — keyed by ingress `ChannelId`, holds the peer-egress `Channel` + flip-flag + ephemeral session metadata) PLUS a `Channel` attribute that caches the registry entry for O(1) on the event loop. Drain (AD-22) enumerates the registry; tear-down removes via `channelInactive`. Both units read/write the same structure.
2. **JWKS cache shape**: `AtomicReference<JwkSet>` (or equivalent immutable key-list) swapped whole on refresh; the cache exposes a `close()` for AD-22 drain ordering. In-place mutation of the cached keys is forbidden (visibility race).

---

## F-7 [HIGH] — AD-19's "tiny loopback HTTP handler on our own Netty" does not fix its event-loop group; risk of sharing the SMPP relay event loop

**A slow `/metrics` scrape (large exposition at 10K pairs) on the SMPP relay event loop is an AD-4 violation. AD-16 ("no Spring web server on the SMPP path") and AD-19 ("our own Netty") leave the event-loop assignment open.**

### The two units

- **E-OBSERVABILITY-METRICS — "/metrics scrape handler," in `observability/`.** Reads AD-19 literally: a tiny Netty HTTP handler on loopback. To keep the scrape off the relay path, allocates a **dedicated** event loop group for the metrics server.
- **E-BOOTSTRAP-MAIN — "Spring Boot main + `SmartLifecycle`," in `bootstrap/`.** Reads AD-16 ("Spring Boot owns lifecycle") and starts the metrics Netty in a `SmartLifecycle` bean. To minimize thread count, reuses the SMPP relay's event loop group (after all, AD-2's "shared event loop for both legs" already shares one group across ingress+egress — adding a third loopback "leg" looks consistent).

### The gap

Neither AD-16 nor AD-19 says whether the metrics HTTP server shares the relay event loop group. AD-2's "shared event loop for both legs" refers to the two relay legs, not metrics; AD-6's "Netty event loops (platform threads, data plane)" doesn't classify the metrics server.

**Incompatibility, concretely:** on a 10K-pair instance the Prometheus exposition can be hundreds of KB; serializing it on the relay event loop (E-BOOTSTRAP-MAIN's build) stalls every splice for the scrape duration — a direct AD-4 violation that only manifests under load (and tanks SM-3's PERF-1 measurement). E-OBSERVABILITY-METRICS's dedicated group adds ~2 platform threads but is clean. Both builds pass AD-16, AD-19, AD-6 individually.

### Closing AD

**TIGHTEN AD-19 — the metrics HTTP server uses a dedicated, hand-managed event loop group; it never shares the SMPP relay event loop group.** Started/stopped via `SmartLifecycle` after the relay group and drained before it. Loopback IPv4 only (already in AD-19); the scrape handler runs no business logic.

---

## F-8 [MEDIUM] — AD-8 fixes the routing-table key (`system_id`) but not the value; FR-AUTH-3 "per-instance" Mode C cert is ambiguous vs per-egress-target

**The Deferred list pushes routing-table format to "config-schema detail," but the value schema determines whether the egress leg can be built. Two teams produce different schemas.**

### The two units

- **E-CONFIG-ROUTING — "Routing table loader," in `config/`.** Reads AD-8 ("immutable post-startup, keyed by `system_id`"), AD-14 (identity preserved), AD-15 (route on `system_id`). Defines the table as `Map<SystemId, HostPort>` — value is just `{host, port}`. Reads FR-AUTH-3 ("per-instance baked client certificates") as: one Mode C client cert per instance, used for every egress target.
- **E-RELAY-EGRESS — "Egress leg dialer + TLS context," in `relay/`.** Expects to need a TLS-context selector per egress target (different carriers, different client certs). Defines the table as `Map<SystemId, EgressTarget>` where `EgressTarget = {host, port, tlsContextId}`. Reads FR-AUTH-3 as per-target (the operator's PKI issues distinct certs per carrier relationship).

### The gap

AD-8 fixes the key only; the value schema is deferred but load-bearing for the egress epic. FR-AUTH-3's "per-instance" can be read as either per-runtime-instance or per-egress-target-instance.

**Incompatibility, concretely:** an operator with two carrier relationships mounts two client certs; on E-CONFIG-ROUTING's build the second cert is unused (and AD-17's fail-fast may reject it as "extraneous"), on E-RELAY-EGRESS's build the single-cert config is rejected as "missing tlsContextId." The routing-table YAML schema each team documents is structurally different.

### Closing AD

**NEW AD-29 — "Routing-table value schema + Mode C cert scope."**

1. Routing-table value = `{host, port, tlsContextId?}` where `tlsContextId` is optional; if absent, the instance-level TLS context is used.
2. FR-AUTH-3 is clarified: Mode C client cert is **per-instance** by default (one cert used for all egress targets); per-target cert IDs are permitted via the optional `tlsContextId` and an explicit `tls.contexts` map in config. Both teams converge on one schema.

---

## F-9 [MEDIUM] — Max SMPP frame size and direct-memory budget are uncoordinated across AD-21, SEC-2, REL-2

**`SmppFrameDecoder`'s max-frame-size and the relay's direct-memory budget (AD-21) are chosen independently. At 10K concurrent pairs they diverge into OOM.**

### The two units

- **E-CODEC-FRAME — "`SmppFrameDecoder` + max frame enforcement," in `companions-codec`.** Per SEC-2 ("robust against oversized frames") enforces a max. Picks SMPP's theoretical max (~64 KiB — `message_payload` TLV can carry 65535 octets).
- **E-RELAY-SPLICE — "Allocator + backpressure," in `relay/`.** Per AD-21 ("one shared `PooledByteBufAllocator`; size `MaxDirectMemorySize`") and REL-2 (backpressure) sizes direct memory assuming an average frame near 256 bytes (a `submit_sm` typical); budgets ~100 MiB direct memory for 10K pairs × N in-flight frames.

### The gap

AD-21 says "size `MaxDirectMemorySize`" but doesn't fix the per-channel inbound budget or the max frame size that drives it. SEC-2 says oversized frames are rejected but doesn't fix the bound.

**Incompatibility, concretely:** if real traffic includes 64-KiB `submit_sm` bursts, peak direct memory is `10K pairs × max-frame × in-flight-depth` = far above E-RELAY-SPLICE's 100 MiB budget → OOM at the allocator (or `OutOfDirectMemoryError`) under load that both units individually allow. Conversely if E-RELAY-SPLICE caps the inbound queue at 1 frame, E-CODEC-FRAME's 64-KiB max is moot but legitimate `message_payload` traffic is backpressured unexpectedly.

### Closing AD

**NEW AD-30 — "Max frame size + per-channel inbound budget + direct-memory derivation."**

1. `SmppFrameDecoder` max `command_length` = a single pinned value (suggest 65 536 octets — covers `message_payload` TLV max); frames exceeding are dropped + the channel closed (fail-closed, SEC-2).
2. Per-channel inbound queue depth (in framed-PDU buffers) is bounded; `AUTO_READ=false` + the write-completes-gates-read backpressure (AD-2) is the trip-wire, with an explicit low-water mark to re-arm read.
3. `MaxDirectMemorySize` is derived from `(max_frame × max_inbound_depth × concurrent_pairs × safety_factor)` and exposed via `ByteBufAllocatorMetric` (AD-21). One formula, named in the spine, so the codec max and the allocator budget cannot drift.

---

## Cross-cutting notes (non-blocking but worth fixing while the spine is open)

- **Internal contradiction** (must fix regardless of F-1): line 59 (`BA -->|verdict → flip flag → splice| EL`) vs AD-2 line 74 (RelayHandler flips). The spine cannot ship with two flippers named.
- **"Every bind" language in AD-12** is the root of F-2's role ambiguity; tighten the wording when F-2's fix is applied.
- **The Deferred list** ("routing-table format … config-schema detail", "DLR-splice byte mechanics … belongs in `relay` tests") is fine as deferred *detail*, but the *shape invariants* (key AND value schema, frame size, allocator budget) are not detail — they are the things two teams diverge on. Move them from Deferred into ADs (F-8, F-9).
- **`ScopedValue` (JEP 506 final)** — AD-5 is correct that it's stable on JDK 25; F-2's verifier signature leans on it, so the spine should name it as the request-context carrier so two teams don't pick `ThreadLocal` vs `ScopedValue`.

---

## Summary of ADs to add / tighten

| # | Action | Closes |
|---|--------|--------|
| AD-2 | TIGHTEN — single flipper (RelayHandler), decoded `bind_*_resp` ROK trigger, post-couple teardown path (unbind opaque or named detector) | F-1 |
| AD-12 | TIGHTEN — owning package, signature, sealed verdict shape, executor, canonical role (ingress only) | F-2 |
| AD-17 | TIGHTEN — 2×3 (role × mode) required-config matrix | F-3 |
| AD-13 | BROADEN — trust-store-never-`cacerts` applies to every peer-cert path, not only Mode C (or add AD-26) | F-3 |
| AD-25 | NEW — bind→splice transition end-to-end (the load-bearing parts of F-1 not covered by tightening AD-2) | F-1 |
| AD-26 | NEW (optional form) — trust-store source for every peer-auth path (alt to broadening AD-13) | F-3 |
| AD-27 | NEW — intra-`proxy` ownership seams (bind-family set in codec; `SpliceObserver` in observability) | F-4 |
| AD-28 | NEW — bounded delegating executors hand-managed / platform-thread / shared; JWKS refresh on hand-rolled VT | F-5 |
| AD-8 | TIGHTEN — `ConnectionRegistry` as the per-bind state home; `AtomicReference` JWKS cache shape | F-6 |
| AD-19 | TIGHTEN — metrics HTTP server on a dedicated event loop group, never the relay group | F-7 |
| AD-29 | NEW — routing-table value schema + Mode C cert scope (per-instance default) | F-8 |
| AD-30 | NEW — max frame size + per-channel inbound budget + direct-memory derivation formula | F-9 |

Apply at least F-1, F-2, F-3, F-4 before splitting the first epic; the rest can land with their owning epic but should be fixed in the spine before that epic starts.
