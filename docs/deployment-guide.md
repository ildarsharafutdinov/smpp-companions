# Deployment Guide — per-cell walkthroughs in both packaged shapes

> **Status:** authored with Story 6.1 T2 (2026-09-13); the machine-proven matrix trued and the
> conformance-run section added by Story 6.2 T4 (2026-09-16) — this page is documentation only,
> nothing in the repository parses it (owner rule 2026-09-10: no Java test's oracle is a markdown
> page), so page↔reality coherence is a review-time duty: a change to any launch fact goes
> through a story that touches the deploy code AND this page · **Audience:** operators taking
> the proxy from a clean checkout to a running instance, in either packaged shape · **Oracle:**
> the as-built deploy shapes and their test rigs — `proxy/src/docker/Dockerfile`,
> `buildSrc/src/main/kotlin/smpp/deploy/`, `PackagedBootSmokeTest`, `DockerImageBootSmokeTest`,
> `DockerSecretsE2eTest`, the composed suites (`ComposedChainE2eTest`, `ComposedPackagedE2eTest`,
> `ComposedDockerE2eTest`), `TestCompanionConfigs` — where this page and the code disagree, the
> code wins and this page is buggy.

There is exactly one deploy artifact and two packaged shapes for it. The JAR
(`proxy/build/libs/proxy.jar`) and the Docker image (distroless, tag `smpp-proxy:local`) package
the SAME jar bytes over the same jlink runtime, carry the SAME JVM flag set in their launch
definitions, and expose the SAME configuration channel — Spring run args. Neither shape authors
its own flags; both launch definitions are pinned by the
[flag contract](operator-jvm-flag-contract.md), which this page cross-links and never duplicates.

**What "running" means here.** A booted instance is READY when its stdout carries the
`startup_summary` JSON line — by then the whole fail-fast surface (config validation, the AD-30
memory self-check, the TLS material loads, the listeners) has passed. Readiness dials nothing:
the SMSC is dialed per bind, and the OIDC provider is first touched at the first bind's
adjudication. The walkthrough below therefore reaches READY with placeholder endpoints; a
COUPLED bind additionally needs the IdP and SMSC realities described in the trust section below.

**What this page does not cover** (each fact has one home): the JVM launch flags —
[`operator-jvm-flag-contract.md`](operator-jvm-flag-contract.md); the `companion.*` key reference
and the AD-17 role×mode matrix — [`configuration.md`](configuration.md); the JSON log events,
`/metrics`, the deny surface, and shutdown internals — [`runbooks.md`](runbooks.md); the TLS
cipher policy — [`cipher-allowlist-policy.md`](cipher-allowlist-policy.md). There are no
performance numbers anywhere in this documentation (Epic 7 will publish them) and no sandbox rig
(that is Story 6.3's, [`../sandbox/README.md`](../sandbox/README.md)). The packaged-shape
conformance run — the composed two-instance journeys — has its own section at the bottom of this
page (Story 6.2 landed it there).

## The two shapes

### Shape 1 — the runnable JAR

```console
$ ./gradlew :proxy:bootJar
$ java --enable-preview -XX:+UseZGC -XX:MaxDirectMemorySize=6442450944 -Djava.net.preferIPv4Stack=true \
      -jar proxy/build/libs/proxy.jar <cell args…>
```

The four flags are the contract set — a minimum set every launch must carry; see the
[flag contract](operator-jvm-flag-contract.md) for what each one is for and the one-set rule for
additions. The launch presumes the pinned JDK 25 build (`temurin-25.0.3+9.0.LTS`, pinned by the
environment via asdf `.tool-versions`). Cell configuration rides the args after the jar path —
Spring run args, the highest-precedence channel (the channel order lives in
[configuration.md](configuration.md)). File paths in args resolve from the process's working
directory; use absolute paths if you launch from elsewhere.

### Shape 2 — the distroless Docker image

```console
$ ./gradlew :proxy:dockerImage        # builds and tags smpp-proxy:local
$ docker run -d --name smpp-proxy -p 2775:2775 <mounts…> smpp-proxy:local <cell args…>
```

Facts an operator needs about the image (source: `proxy/src/docker/Dockerfile`):

- **Base:** `gcr.io/distroless/base-debian12:nonroot` — glibc, no shell, no package manager. The
  process runs as the fixed non-root user/group **65532** (`USER nonroot:nonroot`).
- **Payload:** exactly two COPY layers — the jlink runtime at `/opt/jre/` and the one jar at
  `/opt/proxy.jar`. No secret material rides any layer; secrets are runtime mounts.
- **The exec-form ENTRYPOINT carries the contract flag set** — `/opt/jre/bin/java` + the four
  flags + `-jar /opt/proxy.jar`. Java is PID 1, so `docker stop`'s SIGTERM reaches the JVM and
  the graceful drain runs before the exit. Arguments after the image name append to the
  ENTRYPOINT as ordinary Spring run args — the same channel, the same precedence, as args after
  the jar path in Shape 1.
- **`./gradlew :proxy:dockerImage` is deliberately outside `build`/`check`** — the image's home is
  the Docker daemon, invisible to Gradle, so the task always builds when invoked and Docker's own
  layer cache is the incrementality (a `docker rmi` is never silently skipped over). Building
  requires a reachable daemon.

Two run-level rules for every `docker run` of this image, both pinned by Docker-shape tests:

1. **No extra JVM flags through the environment.** `JDK_JAVA_OPTIONS`, `JAVA_TOOL_OPTIONS`,
   `JAVA_OPTS`, `_JAVA_OPTIONS` would fork the launch away from the contract set — exactly the
   per-shape drift the flag contract forbids. Do not set them on the container.
2. **No `--memory` cap below the AD-30 budget.** Netty allocates SMPP PDU buffers off-heap; the
   contract's `-XX:MaxDirectMemorySize=6442450944` (6 GiB) is direct memory ON TOP of heap and
   metaspace. A container cap inside that budget turns sustained load into an OOM kill (exit
   137) instead of the bounded posture the budget exists to provide. Leave the cap off, or size
   it above the derived budget — and if you retune `companion.memory.*`, retune the flag to
   match ([configuration.md](configuration.md)).

## Preparation common to every cell (AD-18: secrets are file paths)

Every secret the proxy reads is a FILE PATH, never a value — no key exists anywhere that binds
secret material, so a secret cannot arrive by argument or environment by construction. Placeholder
domains in every example: `idp.example.com` (the IdP), `smsc.carrier.example` (the SMSC),
`reverse.internal` (a reverse proxy a forward dials); substitute yours.

The walkthrough keeps its material in a `secrets/` directory beside the working directory (AD-18
paths are arbitrary; the Docker shape conventionally mounts them under `/run/secrets` inside the
container):

```console
$ mkdir -p secrets
# The Keycloak client's secret — one line (leading/trailing whitespace is trimmed on load):
$ printf '%s\n' '<the client secret of your Keycloak client>' > secrets/oidc-client-secret
# The IdP trust store: PKCS12 holding the CA certificate that issued your IdP's TLS certificate
# (at least one trusted certificate entry; PKCS12 is the JDK default — JKS is not supported):
$ keytool -importcert -noprompt -alias idp-ca -file <your-idp-ca.pem> \
          -keystore secrets/idp-truststore.p12 -storetype PKCS12 -storepass changeit
$ chmod 0444 secrets/oidc-client-secret secrets/idp-truststore.p12
```

`0444` is what the Docker shape's UID-65532 read requires (see the mount rationale in the
Docker section below). On the JAR shape the service user owns these files, so owner-only `0400`
is the tighter posture there — prefer it on a multi-user host.

The store password protects the PKCS12's integrity only — the material inside is public
certificates. A trust store NEVER falls back to JDK `cacerts` (AD-13): the path is required, a
store that will not load refuses startup, and so does one with zero trusted entries (SEC-050).
Cells with SMPP-leg TLS (forward A/C, reverse C) carry additional cert/key/trust-store files
prepared the same way — readable files; PEM/key parseability is checked eagerly at boot.

## reverse.mode-b — the zero→running walkthrough (both shapes)

Mode B is the plaintext internet leg: legacy clients connect DIRECTLY to this instance (there is
no forward proxy in Mode B), it still adjudicates every bind ("plaintext + ROPC"), and it is
opt-in — without the acknowledgment the boot refuses:

```text
companion.reverse.mode-b (plaintext) requires explicit opt-in (companion.reverse.mode-b.acknowledged=true) — refusing to start (SEC-052/AD-17).
```

### Shape 1 — the JAR launch

From the repository root (the jar path below is `./gradlew :proxy:bootJar`'s output):

```console
$ java --enable-preview -XX:+UseZGC -XX:MaxDirectMemorySize=6442450944 -Djava.net.preferIPv4Stack=true \
      -jar proxy/build/libs/proxy.jar \
      --companion.bind.host=127.0.0.1 \
      --companion.reverse.mode-b.smsc.host=smsc.carrier.example \
      --companion.reverse.mode-b.smsc.port=2775 \
      --companion.reverse.mode-b.acknowledged=true \
      --companion.reverse.mode-b.oidc.provider-url=https://idp.example.com/realms/smpp-companions \
      --companion.reverse.mode-b.oidc.client-id=smpp-client-confidential \
      --companion.reverse.mode-b.oidc.client-secret-path=secrets/oidc-client-secret \
      --companion.reverse.mode-b.oidc.trust-store.path=secrets/idp-truststore.p12 \
      --companion.reverse.mode-b.oidc.trust-store.password=changeit \
      --companion.reverse.mode-b.oidc.timeout=4s \
      --companion.reverse.mode-b.oidc.max-in-flight=64
```

Every common key not stated rides the jar's `application.yml` defaults
(`companion.bind.port=2775`, `companion.metrics.port=9090`,
`companion.shutdown.drain-timeout=10s`, the memory trio, the TLS lists) — required
branch keys have no defaults anywhere and must all be stated, exactly as above. **Two expected
observations**, in this order, on stdout (a pure JSON-lines stream):

1. **The Mode B banner** — ONE WARN-level JSON line carrying this text verbatim, newlines
   escaped (`CompanionModeBWarning`), fired during the context refresh the moment the config
   validation passes:

```text
************************************************************
* MODE B (plaintext) is ACTIVE on a REVERSE instance.
* SMPP passwords transit the network in PLAINTEXT.
* Mode B is opt-in and was acknowledged via
* companion.reverse.mode-b.acknowledged=true.
* Restrict the reverse<->SMSC leg; this is an accepted risk.
************************************************************
```

2. **The readiness line** — one INFO JSON line containing `"event":"startup_summary"`,
   `"role":"reverse"`, `"mode":"b"`, `"smpp_bind_host":"127.0.0.1"`, `"smpp_bind_port":2775`,
   `"metrics_port":9090`, and the AD-30 interlock: `"memory_budget_bytes"` equals
   `"direct_memory_ceiling_bytes"` equals `6442450944` (the yml-default derivation
   65536 × 64 × 1024 × 1.5 against the contract flag — retune either side without the other and
   this boot refuses instead of starting).

That accepted risk is registered, not accidental: plaintext SMPP passwords on the internet leg —
opt-in plus the loud warning, and it starts (the Accepted-Risk Register's Mode B entry). The
`bind.host` in the walkthrough is loopback; a real internet-leg listener SHOULD be scoped to the
interface it is reachable on (`0.0.0.0` is the shipped default and binds every interface).

A first bind on `127.0.0.1:2775` couples only when the adjudication allows (IdP reachable, DAG
enabled, JWT issued) and the SMSC dial succeeds — success logs a `"event":"bind_accept"` line
naming the `system_id`; every other outcome denies fail-closed with ONE generic status on the
wire and the rich verdict only in the log line and metrics (the deny-surface table lives in
[runbooks.md](runbooks.md)). Stop the instance with `kill -TERM <pid>`: the graceful walk drains
and the process exits **143** — the JVM convention for a hook-completed SIGTERM shutdown (a boot
crash is 1; a forcible kill leaves 137).

### Shape 2 — the canonical `docker run` recipe

The same cell, the same args — they ride after the image name. Mount the two secret files
read-only at `/run/secrets`:

```console
$ docker run -d --name smpp-proxy \
      -p 2775:2775 \
      -v "$(pwd)/secrets/oidc-client-secret:/run/secrets/oidc-client-secret:ro" \
      -v "$(pwd)/secrets/idp-truststore.p12:/run/secrets/idp-truststore.p12:ro" \
      smpp-proxy:local \
      --companion.bind.host=0.0.0.0 \
      --companion.reverse.mode-b.smsc.host=smsc.carrier.example \
      --companion.reverse.mode-b.smsc.port=2775 \
      --companion.reverse.mode-b.acknowledged=true \
      --companion.reverse.mode-b.oidc.provider-url=https://idp.example.com/realms/smpp-companions \
      --companion.reverse.mode-b.oidc.client-id=smpp-client-confidential \
      --companion.reverse.mode-b.oidc.client-secret-path=/run/secrets/oidc-client-secret \
      --companion.reverse.mode-b.oidc.trust-store.path=/run/secrets/idp-truststore.p12 \
      --companion.reverse.mode-b.oidc.trust-store.password=changeit \
      --companion.reverse.mode-b.oidc.timeout=4s \
      --companion.reverse.mode-b.oidc.max-in-flight=64
```

Expected observations, with `docker logs smpp-proxy`: the same two lines as the JAR shape, in
the same order — the Mode B WARN banner, then the `startup_summary` line (here naming
`"smpp_bind_host":"0.0.0.0"`).
Then:

```console
$ docker stop --timeout 30 smpp-proxy
$ docker inspect --format '{{.State.ExitCode}}' smpp-proxy
143
```

`--timeout 30` is deliberate: the daemon's default stop wait is 10s, while a walk with live pairs
can spend the full 10s drain deadline plus release and quiesce — the walk is bounded by the 30s
`spring.lifecycle.timeout-per-shutdown-phase` ceiling, and a stop wait shorter than that window
lets the daemon SIGKILL the walk mid-drain, turning the exit code into 137.

The rules baked into the recipe, each pinned by a Docker-shape test:

- **Published SMPP port only.** `-p 2775:2775` and nothing else. The `/metrics` endpoint binds
  the literal `127.0.0.1` inside the container — loopback is its only authentication, so there is
  deliberately nothing to publish, and no `-p 9090` finds anything listening. In-container access
  rides `docker exec` of the image's own java (the image has no shell); the scrape reference
  lives in [runbooks.md](runbooks.md).
- **The listener must bind `0.0.0.0` inside the container.** A published port forwards to the
  container's own interface; a loopback-scoped `bind.host` inside the container is unreachable
  through the publish. Scope at the publish/host layer instead.
- **Mounted secret files must be readable by UID 65532.** The image's process runs as 65532; a
  mounted file it cannot read refuses startup BEFORE any listener binds (exit 1, no
  `startup_summary` — no partial start):

```text
companion.reverse.mode-b.oidc.client-secret-path=/run/secrets/oidc-client-secret does not exist (OIDC client secret file missing) — refusing to start (SEC-060/AD-18).
companion.reverse.mode-b.oidc.client-secret-path=/run/secrets/oidc-client-secret is not readable (OIDC client secret file permissions) — refusing to start (SEC-060/AD-18).
```

  World-readable mode (`0444`, as the preparation step sets) or ownership by 65532 both satisfy
  the read — bind mounts preserve the host file's mode and owner, which is exactly how the two
  refusals above are produced (a file UID 65532 cannot read — root-owned `0600`, or an
  owner-only mode under another UID — is the second one). Two adjacent states refuse on
  neighboring arms of the same SEC-060 check: an empty or whitespace-only secret file
  (`is empty (or whitespace only) — refusing to start (SEC-060/AD-18)`), and — the classic
  typo'd `-v` source — Docker silently creating a DIRECTORY at a nonexistent source path, which
  the proxy answers with `is a directory, not a file (OIDC client secret) — refusing to start
  (SEC-060/AD-18)` instead of a mount error.
- **No args at all is a refusal, by design.** A bare `docker run --rm smpp-proxy:local` boots the
  yml defaults — which configure no cell — and exits 1 with the AD-17 zero-branch refusal:

```text
no companion.<role> branch is configured — exactly one is required (AD-17) — refusing to start.
```

## The other four cells

Same shapes, same rules — only the material and the branch args change (the AD-17 matrix in
[configuration.md](configuration.md) states required/optional/forbidden per cell; the forward
cells' full key reference lives there too). A Docker launch of any of these cells is the recipe
above with the cell's args after the image name and the cell's own files mounted — nothing in
the recipe is mode-b-specific beyond the args. `<contract flags>` below is the four-flag set
from Shape 1.

### reverse.mode-a — one-way TLS listener

The internet leg is TLS with the instance presenting its server certificate and validating no
peers. Required: `smsc`, `server-cert`, `oidc`. No trust store exists on this branch — one-way
TLS never validates peers, so the key is structurally absent (a stray one refuses).

```console
$ java <contract flags> -jar proxy/build/libs/proxy.jar \
      --companion.bind.host=<the internet-leg interface> \
      --companion.reverse.mode-a.smsc.host=smsc.carrier.example \
      --companion.reverse.mode-a.smsc.port=2775 \
      --companion.reverse.mode-a.server-cert.cert-path=secrets/reverse-server.crt \
      --companion.reverse.mode-a.server-cert.key-path=secrets/reverse-server.key \
      --companion.reverse.mode-a.oidc.provider-url=https://idp.example.com/realms/smpp-companions \
      --companion.reverse.mode-a.oidc.client-id=smpp-client-confidential \
      --companion.reverse.mode-a.oidc.client-secret-path=secrets/oidc-client-secret \
      --companion.reverse.mode-a.oidc.trust-store.path=secrets/idp-truststore.p12 \
      --companion.reverse.mode-a.oidc.trust-store.password=changeit \
      --companion.reverse.mode-a.oidc.timeout=4s \
      --companion.reverse.mode-a.oidc.max-in-flight=64
```

Boots with the analogous banner, verbatim (`CompanionModeAWarning`):

```text
************************************************************
* MODE A (one-way TLS) is ACTIVE on a REVERSE instance.
* The reverse CANNOT authenticate the connecting forward
* (one-way TLS presents a cert; it never validates peers).
* ACL-isolate the listener (companion.bind.host) or use
* Mode C mTLS. This is an ACCEPTED RISK (AD-12 register).
************************************************************
```

The register entry the banner names is a submission oracle, not a harvest point: any peer that
reaches this listener can SUBMIT binds — the reverse still adjudicates every credential and the
SMSC remains the sole credential authority, so a fake forward harvests nothing, but credential
guesses can be driven through the ROPC screen. The remediation is the banner's own line:
ACL-isolate the listener to your forward-proxy hosts (`companion.bind.host` plus network ACLs)
or run Mode C.

### reverse.mode-c — mTLS listener

Mode C is Mode A's material plus a trust store that REQUIREs the forward's per-instance client
certificate. Required: `smsc`, `server-cert`, `trust-store`, `oidc`:

```console
$ java <contract flags> -jar proxy/build/libs/proxy.jar \
      --companion.bind.host=<the internet-leg interface> \
      --companion.reverse.mode-c.smsc.host=smsc.carrier.example \
      --companion.reverse.mode-c.smsc.port=2775 \
      --companion.reverse.mode-c.server-cert.cert-path=secrets/reverse-server.crt \
      --companion.reverse.mode-c.server-cert.key-path=secrets/reverse-server.key \
      --companion.reverse.mode-c.trust-store.path=secrets/truststore.p12 \
      --companion.reverse.mode-c.trust-store.password=changeit \
      --companion.reverse.mode-c.oidc.provider-url=https://idp.example.com/realms/smpp-companions \
      --companion.reverse.mode-c.oidc.client-id=smpp-client-confidential \
      --companion.reverse.mode-c.oidc.client-secret-path=secrets/oidc-client-secret \
      --companion.reverse.mode-c.oidc.trust-store.path=secrets/idp-truststore.p12 \
      --companion.reverse.mode-c.oidc.trust-store.password=changeit \
      --companion.reverse.mode-c.oidc.timeout=4s \
      --companion.reverse.mode-c.oidc.max-in-flight=64
```

Note the TWO trust stores: the branch's (`…mode-c.trust-store.*`) anchors the CA(s) issuing your
forwards' client certificates and drives `clientAuth(REQUIRE)` — a client presenting no or an
untrusted certificate never completes TLS (AD-13: REQUIRE, never WANT); the `oidc.trust-store.*`
anchors the IdP's TLS certificate, as in every reverse cell. They are different stores for
different anchors; do not merge them by accident.

### forward.mode-a — trusted-leg listener, one-way TLS dial

The forward is the trusted-side relay: its listener is PLAINTEXT on the trusted network (your
legacy carrier clients connect here — `companion.bind.port` is their port), it holds NO OIDC
material (the reverse adjudicates; AD-12 amended 2026-08-18), and per SMPP session it dials the
reverse over one-way TLS. Required: `trust-store` (anchors the reverse's server certificate) and
`routing` (the allow-list). No `smsc` node exists on the forward — each routing entry IS the
dial target:

```console
$ java <contract flags> -jar proxy/build/libs/proxy.jar \
      --companion.bind.host=<the trusted-leg address> \
      --companion.forward.mode-a.trust-store.path=secrets/truststore.p12 \
      --companion.forward.mode-a.trust-store.password=changeit \
      --companion.forward.mode-a.routing[0].system-id=carrierOne \
      --companion.forward.mode-a.routing[0].host=reverse.internal \
      --companion.forward.mode-a.routing[0].port=2776
```

The routing table is a `system_id` allow-list mapped 1:1 to egress targets (AD-29: v1 is 1:1 —
each entry is the reverse proxy that forward dials for that id). A bind whose `system_id` is not
in the table denies fail-closed (no default route, AD-11); the table must be non-empty and its
ids unique (violations refuse startup, SEC-058/AD-29). The `startup_summary` line of a forward
instance names `"role":"forward"` and lists the ids under `routing_system_ids`.

### forward.mode-c — trusted-leg listener, mTLS dial

Mode C adds the per-instance client certificate presented on the dial — one cert per runtime
instance, never a shared golden-image key (FR-AUTH-3); rotation is re-deploy:

```console
$ java <contract flags> -jar proxy/build/libs/proxy.jar \
      --companion.bind.host=<the trusted-leg address> \
      --companion.forward.mode-c.client-cert.cert-path=secrets/forward-client.crt \
      --companion.forward.mode-c.client-cert.key-path=secrets/forward-client.key \
      --companion.forward.mode-c.trust-store.path=secrets/truststore.p12 \
      --companion.forward.mode-c.trust-store.password=changeit \
      --companion.forward.mode-c.routing[0].system-id=carrierOne \
      --companion.forward.mode-c.routing[0].host=reverse.internal \
      --companion.forward.mode-c.routing[0].port=2776
```

Optional per-target override: a routing entry may carry `tls-context-id` selecting a
`companion.forward.tls-contexts.<id>.cert-path`/`key-path` pair presented on that entry's dials
(a dangling id refuses startup, SEC-098); an entry without one uses the instance-level default
above. The override map exists only on the forward role — only the forward dials TLS under the
[B] topology (AD-29 amendment, 2026-08-26).

## The IdP the reverse cells authenticate against (trust disclosure)

Every reverse cell adjudicates each bind's password against your OIDC provider over TLS, and
v1's adjudication is **ROPC** — the OAuth 2.0 Resource Owner Password Credentials grant, which
Keycloak exposes as **Direct Access Grants**. Three things every operator must know (the
Accepted-Risk Register's ROPC entry — recorded verdicts, not fresh research):

1. **v1 authenticates via ROPC / Direct Access Grants.** The proxy exchanges the bind's
   credentials at the provider's token endpoint and admits the bind on a JWT access-token
   response. There is no alternative grant in v1; the verifier port localizes a future rework to
   one adapter, but the dependency itself stands.
2. **ROPC is on a removal track.** RFC 9700 (BCP) says clients MUST NOT use it, and OAuth 2.1
   removes it. This deployment's first-party/headless framing does not neutralize the normative
   language or the trajectory. It is the single most fragile external dependency in the trust
   model, accepted knowingly.
3. **Pin your Keycloak build: ≥26.7.0, re-validated each minor.** The recorded verdict
   (2026-08-08): Keycloak 26.7.0 ships Direct Access Grants and per Keycloak release policy the
   grant cannot be removed before KC 27; there is no upstream LTS and minors reach end-of-life
   in roughly three months, so every minor you adopt must be re-validated for the grant. A 26.x
   minor could tighten ROPC without a formal removal notice — watch each release note.

And one enablement prerequisite that is OFF by default: **Direct Access Grants are per-client
and disabled since Keycloak 26.2.** Enable the grant on the confidential client the proxy uses,
or every bind denies fail-closed at FIRST bind — the proxy makes no provider call at startup
(the token endpoint is only DERIVED from `provider-url`), so a provider misconfiguration
surfaces exactly there, as the starred `OPERATOR_WARNING` banner naming the derived token
endpoint and the `provider-url`, followed by one-liner repeats per further bind (the banner's
full text and the diagnosis flow live in [runbooks.md](runbooks.md)). Two related provider-side
requirements: `provider-url` must be the Keycloak REALM base (the token endpoint is derived as
`<provider-url>/protocol/openid-connect/token`), and the client/realm must issue JWT access
tokens — an opaque token response denies fail-closed with `OPAQUE_TOKEN_WARNING`. Both policy
blocks are documented with their dates in [configuration.md](configuration.md).

## Base-image policy — mutable tag, documented (BH6)

The Docker base image is pinned by the MUTABLE tag `gcr.io/distroless/base-debian12:nonroot`
(`proxy/src/docker/Dockerfile`). **Owner decision (2026-09-12, BH6): keep the mutable tag and
document the posture.** The tradeoff: CVE-freshness — distroless base updates flow into every
rebuild automatically — against rebuild reproducibility — a rebuild after an upstream push can
change glibc and the base environment silently, while everything else in the deploy shape is
pinned (JDK by asdf, flags by the contract page, the runtime module set by jdeps). The future
home of any digest pin is the release/publish tooling, which deliberately does not exist yet
(owner stance 2026-09-11: release/publish untouched). Until such tooling lands, an operator who
needs reproducible bases pins the digest in their own deployment pipeline, knowingly giving up
the freshness half.

## What is machine-proven about these shapes (honest evidence)

The packaged shapes carry real e2e rows — exactly what they cover, and what they do not:

- **DEPLOY-015 (JAR):** `PackagedBootSmokeTest` boots the real jar with the contract flags on the
  reverse.mode-b cell, asserts the `startup_summary` fields including the AD-30 interlock, drives
  one real-socket bind→relay round (ROK `bind_transceiver_resp`, byte-exact `submit_sm` /
  `deliver_sm` on both legs), scrapes `/metrics`, and walks SIGTERM → the ordered drain WARN →
  exit 143. Its second row proves the preview arm: the identical launch minus `--enable-preview`
  exits 1 with `UnsupportedClassVersionError` naming the flag.
- **DEPLOY-005 (Docker parity):** `DockerImageBootSmokeTest` mirrors that journey on the image
  built from the same jar bytes — identical stdout and wire literals, ENTRYPOINT ≡ the flag
  constant, `docker stop` → 143 with the ordered drain WARN (DEPLOY-006).
  `DockerSecretsE2eTest` adds the secrets contract end to end: the non-root UID 65532 reads the
  mounted files (live `/proc` proof, DEPLOY-007), a secret VALUE in the environment is inert —
  no key exists to bind it — the two bad-file refusals quoted above (DEPLOY-009), and a
  byte-scan proving no secret material rides any image layer (SEC-098).
- **E2E-001 (the composed two-instance chain, Story 6.2):** the flagship topology runs COMPOSED
  in three rungs — two full application contexts in one JVM (`ComposedChainE2eTest`), two
  `java -jar` subprocesses of the one jar under the contract flags with file-path secrets
  (`ComposedPackagedE2eTest`), and two containers of the one image (`ComposedDockerE2eTest`).
  Every rung wires the as-built [B] chain — `forward.mode-c` dials `reverse.mode-c` per SMPP
  session over the Mode C mTLS leg, the REVERSE (not the forward) ROPC-adjudicates every bind
  through the real verifier against the TLS token stand-in, the reverse dials the SMSC — and a
  jSMPP 3.0.2 ESME (an independent stack, COMP-1's interop point) drives the legacy leg. The
  ALLOW round: ROK at the ESME, the bind frame VERBATIM at the SMSC (AD-14), `submit_sm`
  byte-intact through both hops, the DLR back on the originating pair (A-1 affinity across two
  proxies), the couple on BOTH instances' `bind_accept` lines and `/metrics` counters. The
  in-session auth-DENY round (the stand-in's 401 arm): ONE generic `ESME_RBINDFAIL` on the wire
  then close, NO couple anywhere, the rich verdict only in the reverse's `bind_reject` line and
  `relay_binds_rejected_total`. The two packaged rungs additionally prove REL-3 composed:
  SIGTERM / `docker stop` to each instance with the pair open → the ordered
  `startup_summary < bind_accept < drain WARN` stream → exit **143** both (the forward is
  stopped first with the live pair; the reverse's pair dies with the forward's drain, so its
  walk short-circuits on an empty registry — still a clean 143). The in-JVM rung adds a full-boot
  Mode C REQUIRE-negative: a foreign-CA client dial fails the reverse's REQUIRE handshake below
  SMPP — the same generic collapse at the ESME, no SMPP byte anywhere.
- **What is NOT covered by packaged-shape e2e:** the mode A cells — no packaged row before
  Story 6.2, none after: the ratified journey-widening decision (owner 2026-09-13) widened
  MODE C composed plus the in-session auth-DENY round into both shapes (the bullets above) and
  deliberately left mode A with the in-JVM loopback suite (`TlsModesLoopbackE2eTest` owns
  composed mode A at relay altitude) plus this shape pair's structural sameness (one jar, one
  arg channel, one flag set — the DEPLOY-005 parity argument). Mode B's packaged coverage stays
  the reverse-b smoke journeys and startup refusals above (mode B is single-instance by
  construction — there is no forward to compose). The adjudication IdP in every composed rung
  is the deterministic TLS token stand-in, not a live Keycloak (the live adapter-vs-Keycloak
  proof is the 3.2 live suite's). The SMSC-side non-ROK verbatim-forward journey and the proxy
  against a real third-party SMPP stack (Kannel) are Story 6.3's. Read the mode A walkthrough
  above honestly: its configuration is fail-fast-validated and the cell is exercised by the
  in-JVM and loopback suites, but no packaged-shape test has driven a bind through it.

## The packaged-shape conformance run (Story 6.2)

The composed journeys above are ordinary test-suite rows: they run inside `./gradlew clean build`
on any machine — the Docker rung skips with an explicit `disabledWithoutDocker` reason when no
daemon is reachable, never a silent green — and there is no separate "conformance tier" wiring
(no tag filters, no special task). The targeted manual run — what an operator or reviewer
executes to re-prove the matrix on the spot — is ONE command from the repository root (the
pinned JDK 25 of `.tool-versions`, and a Docker daemon for the third rung):

```console
$ ./gradlew :proxy:test --tests '*Composed*' --console=plain
```

The selector matches exactly three suites (a selector that matches nothing FAILS the task rather
than passing silently; the three classes' per-row results land in the JUnit XML named below —
on a green plain-console run the classes are not listed in stdout):

| Suite (`proxy/src/test/…/bootstrap/`) | Rung | Rows |
|---|---|---|
| `ComposedChainE2eTest` | two full application contexts in one JVM | 3 — allow, auth-DENY, Mode C REQUIRE-negative |
| `ComposedPackagedE2eTest` | two `java -jar` subprocesses (contract flags, file-path secrets) | 2 — allow (+ SIGTERM → 143 each), auth-DENY |
| `ComposedDockerE2eTest` | two containers of the one image (through the shared test rig) | 2 — allow (+ `docker stop` → 143 each), auth-DENY |

Expected result with a daemon reachable: `BUILD SUCCESSFUL`, 7 rows, 0 failed, 0 skipped. Without
a daemon the Docker rung skips with its stated reason and the other two rungs still run (5 rows).
Each row names its expected observations per surface — the wire literals (the one generic
`ESME_RBINDFAIL` 0x0000000D collapse; the bind/submit bodies pinned byte-exact at the SMSC), the
JSON log events (`startup_summary`, `bind_accept`, `bind_reject`, the drain WARN), and the
`/metrics` counters per instance — so a failing row states which hop failed, with the failing
instance's own captured output. Per-row detail (names, durations) lands in the JUnit XML under
`proxy/build/test-results/test/TEST-smpp.companion.proxy.bootstrap.Composed*.xml`. (Wire
exactness: the bind and `submit_sm` bodies are pinned byte-exact at the SMSC; the DLR's
`short_message` payload is asserted byte-equal at the ESME it must return to, with its
`deliver_sm_resp` receipt observed back on the same SMSC session.)

The pre-existing single-instance packaged rows — the reverse-b smoke and the Docker
secrets/refusal contract — run the same way under their own selectors:

```console
$ ./gradlew :proxy:test --tests '*PackagedBootSmokeTest' --tests '*DockerImageBootSmokeTest' \
      --tests '*DockerSecretsE2eTest' --console=plain
```

Expected result with a daemon reachable: `BUILD SUCCESSFUL`, 9 rows (2 + 3 + 4), 0 failed,
0 skipped. Without a daemon the two Docker suites skip with their stated reasons and the JAR
smoke's 2 rows still run.

## Cross-references

- [`operator-jvm-flag-contract.md`](operator-jvm-flag-contract.md) — the four launch flags, the
  `MaxDirectMemorySize` ↔ `companion.memory.*` interlock, the documented
  `spring.main.lazy-initialization` deviation.
- [`configuration.md`](configuration.md) — every `companion.*` key with type/default/guard, the
  AD-17 role×mode matrix, the OIDC policy blocks, the retired keys.
- [`runbooks.md`](runbooks.md) — the JSON log-event and `/metrics` references, the deny-surface
  table (where each denial flavor surfaces), shutdown/exit semantics, `OPERATOR_WARNING`
  diagnosis, Mode A ACL isolation, JFR/dump hygiene.
- [`cipher-allowlist-policy.md`](cipher-allowlist-policy.md) — the cipher allowlist, the
  per-context empty-intersection refusal, and the tuning envelope for `companion.tls.*`.
