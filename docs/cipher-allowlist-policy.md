# TLS Cipher-Allowlist Policy — the `companion.tls.*` posture

> **Status:** authored with Story 6.1 T3 (2026-09-13) — this page is documentation only, nothing in
> the repository parses it (owner rule 2026-09-10: no Java test's oracle is a markdown page), so
> page↔reality coherence is a review-time duty: a policy change goes through a story that touches
> `application.yml`, the validators/factories, AND this page · **Audience:** operators deciding
> whether the shipped TLS posture fits their peers, and anyone tuning it · **Oracle:** the shipped
> `proxy/src/main/resources/application.yml` (the lists below match it byte-for-byte) and the
> enforcing code — `CompanionConfigValidator` (bind time), `SmppLegTlsFactory` and
> `IdpSslContextFactory` (per-context construction) — where this page and the code disagree, the
> code wins and this page is buggy.

The proxy pins ONE TLS protocol/cipher policy under `companion.tls.*` (AD-34) and applies it to
**every TLS context either role builds** — there are no per-context cipher knobs and no cipher
keys anywhere else. The posture: **TLS 1.2 minimum, 1.3 preferred, forward-secrecy + AEAD suites
only**; anything weaker refuses startup rather than negotiating down (the AD-17 fail-fast
discipline). The key reference (types, defaults, supply channels) lives in
[configuration.md](configuration.md); this page owns the policy itself and the tuning envelope.

## The shipped default (AD-34)

Exactly what the jar's `application.yml` ships — the lists are reproduced byte-for-byte; a
mismatch between this page and the yml is drift and a bug in one of them:

**Protocols** (`companion.tls.protocols`), 1.3 preferred:

```text
TLSv1.3
TLSv1.2
```

**TLS 1.2 cipher suites** (`companion.tls.tls12-cipher-suites`) — the four ECDHE / AES-GCM
suites:

```text
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

**TLS 1.3 cipher suites** (`companion.tls.tls13-cipher-suites`) — the JDK AEAD set:

```text
TLS_AES_256_GCM_SHA384
TLS_AES_128_GCM_SHA256
TLS_CHACHA20_POLY1305_SHA256
```

Why this shape and no other: every suite is **ECDHE** (ephemeral key exchange — forward secrecy: a
compromised long-term key cannot decrypt past traffic) and **AEAD** (AES-GCM or the ChaCha20
POLY1305 construction). Deliberately absent: CBC-mode suites (weak MAC constructions and the
padding-oracle family), static-RSA key exchange (no forward secrecy), RC4, 3DES, null and anon
suites. The TLS 1.3 set mirrors the same posture — TLS 1.3 mandates forward secrecy at the
protocol level, and restricting it to the JDK's three AEAD suites keeps 1.3 from quietly widening
the surface. The 1.2 list carries ECDSA and RSA variants of both AES strengths because a deployed
SMPP-side certificate may be keyed either way; the proxy does not dictate your PKI's key type.

## Where the policy applies

Every TLS context in the process, both roles:

- **The reverse's internet-leg listener** (`reverse.mode-a` / `reverse.mode-c`) — the
  server-side context presenting your server certificate (mode-c additionally REQUIREs the
  forward's client certificate).
- **The forward's per-session dial contexts** (`forward.mode-a` / `forward.mode-c`) — one client
  context per routing-table entry, plus one load-for-validation context for every unreferenced
  `companion.forward.tls-contexts` entry (all built eagerly at startup, so an unloadable override
  refuses the boot even if no routing entry selects it).
- **The reverse's IdP client context** — the ROPC token-endpoint link's `SSLParameters` (the sole
  trust anchor of the whole adjudication).

`reverse.mode-b` builds no TLS context at all (its legs are plaintext — the accepted-risk cell;
see the [deployment guide](deployment-guide.md)). All contexts are **JDK-provider only**
(`SslProvider.JDK` — no BouncyCastle, no tcnative, no OpenSSL): one JCA provider's behavior
everywhere, and the supported-suite sets the intersections below are computed against are the same
provider's.

## How it is enforced — three fail-fast gates

The policy is enforced at startup, three times over, each gate refusing the boot on failure
(non-zero exit, message naming the key):

1. **Bind-time validation** (`CompanionConfigValidator`, every cell): the protocol list is
   required and non-empty, carries no blank entries, contains **no protocol below TLS 1.2**
   (SEC-061 — `SSLv3`/`TLSv1`/`TLSv1.1` refuse; case-insensitive), and every entry must be
   JDK-supported (a bogus future name like `TLSv9.99` refuses). The **union** of both cipher
   lists must have a non-empty intersection with the JDK-default `SSLContext`'s supported
   suites — an empty or wholly unsupported configured set refuses:

   ```text
   companion.tls cipher suites have an empty intersection with the JDK-default SSLContext supported suites — refusing to start (AD-34). Per-egress-context intersection is Epic 3.
   ```

   (the trailing sentence is historical scaffolding in the shipped message — the per-context
   intersection it points at has long since landed, gate 2 below; the text is quoted as-built)

2. **Per-context construction** (`SmppLegTlsFactory`, the SMPP legs): every context built at
   startup re-intersects the configured suites — and protocols — against that context's supported
   sets; an empty intersection on either axis refuses, naming the context:

   ```text
   companion.tls cipher suites have an empty intersection with the JDK supported suites for the SMPP-leg context [companion.reverse.mode-c] — refusing to start (SEC-100/AD-34, D2 discharge).
   companion.tls.protocols have an empty intersection with the JDK supported protocols for the SMPP-leg context [companion.forward.mode-a (system_id=carrierOne)] — refusing to start (SEC-100/AD-34, D2 discharge).
   ```

   Plus the **applicability cross-check**: the two intersections above run independently, so a
   suite set that intersects the JDK's supported list but applies to NONE of the selected
   protocols (TLS-1.3-only suites with `protocols=[TLSv1.2]`, or 1.2-only suites with
   `protocols=[TLSv1.3]`) would pass both gates and then fail every runtime handshake — it
   refuses instead:

   ```text
   companion.tls cipher suites apply to none of the selected protocols for the SMPP-leg context […] — every handshake would fail — refusing to start (SEC-100/AD-34).
   ```

3. **The IdP client context** (`IdpSslContextFactory`, every reverse cell): the same
   per-context intersection for the provider link, with its own refusal naming the IdP context.
   Here the surviving intersection — never the raw configured lists — becomes the effective
   `SSLParameters` every token call carries, so an unsupported suite name can never reach an
   `SSLEngine`.

The consequence worth internalizing: **the effective suite set is always the intersection, with
your configured order preserved**. The startup gates prove the configured set is JDK-supported
and applicable; they cannot prove a PEER agrees to any of it — a suite the far end does not
implement fails at handshake time (a runtime `DECODE_ERROR`/`PEER_RST`-classified close on the
SMPP leg, per the [runbooks](runbooks.md) close table), not at boot. Interop-verify your tuning
against the real peers.

## The tuning envelope

What you may change, and what each change costs. The knobs are exactly the three keys above
(supply channels and binding rules in [configuration.md](configuration.md)); lists bind
comma-separated in args/env.

- **Reorder.** Order is preference order and survives the intersection — put the suite you want
  negotiated first, first. Free.
- **Narrow (remove suites or protocols).** Always conformant: the intersections just shrink.
  Costs peer interop — every removal is a handshake your weakest legitimate peer may depend on.
  Keep at least one applicable suite per selected protocol or the gates refuse.
- **Widen (add suites).** Anything the JDK provider supports can be added — e.g. the TLS 1.2
  ChaCha20 suites (`TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`,
  `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`), which AD-34 names optional exactly for
  CPU-constrained peers. Costs attack surface — the default's exclusions are the point of the
  policy; re-adding CBC/static-RSA families undoes it while still passing every gate (the gates
  prove support, not wisdom). Do not add what the JDK does not support: unknown names simply
  never intersect (silent no-ops for that name — the set-level gates catch only total emptiness),
  so a typo'd suite name narrows silently. Spell names exactly.
- **Go 1.3-only.** `protocols=[TLSv1.3]` — but then the 1.2 list applies to none of the selected
  protocols and the applicability cross-check REFUSES until you also empty or drop the
  `tls12-cipher-suites` key. The two keys move together.
- **Drop 1.3.** `protocols=[TLSv1.2]` with the 1.3 list still populated — same refusal, mirrored:
  remove the `tls13-cipher-suites` entries too. (Keeping 1.3 enabled and merely reordering the
  1.2 list is the normal posture for a legacy-heavy peer set.)

Guardrails that are NOT tunable — no key exists for any of these:

- **The TLS 1.2 floor.** Sub-1.2 protocol names refuse startup (SEC-061); there is no
  legacy-compatibility switch. A peer that cannot do TLS 1.2 cannot be supported by tuning — that
  is the product decision (AD-34).
- **The JDK provider.** No pluggable provider, no hardware-accelerated OpenSSL path — one JCA
  behavior everywhere.
- **mTLS client-auth on `reverse.mode-c` is `REQUIRE`, never `WANT`** (AD-13) — adjacent to the
  cipher policy, same fail-closed family.
- **Endpoint identification on the forward's dials** (AD-20): hostname routing targets get HTTPS
  verification, raw-IP literals do not (IP-SAN-provisioned certs with verification on is the
  alternative posture). Set per routing entry host, not a cipher matter.

Tuning is per-deployment, at startup, via the config channels — there is no runtime reload (the
whole `companion.*` surface is read once at boot, AD-8); rotation of the policy is a re-deploy.

## Performance boundary

Cipher choice moves both CPU cost and handshake latency, and this page deliberately states no
numbers: no throughput figures, no handshake timings, no suite-vs-suite comparisons. Epic 7's
performance report (Story 7.1, PERF-070/071) is where measured numbers — payload-,
cipher-, and hardware-tagged — will publish. Until then, treat any cipher-tuning performance
decision as unmeasured in this repo.

## Cross-references

- [`configuration.md`](configuration.md) — the `companion.tls.*` key table (types, defaults,
  guards) and the supply channels; the retired-key list (the earlier top-level
  `companion.tls.contexts` location is gone).
- [`deployment-guide.md`](deployment-guide.md) — the per-cell TLS material (server certs, client
  certs, the two trust stores of reverse mode-c) and the ROPC link this policy protects.
- [`runbooks.md`](runbooks.md) — the close-reason table a failed handshake surfaces through, and
  the log/metrics references.
- [`operator-jvm-flag-contract.md`](operator-jvm-flag-contract.md) — the launch flags; the
  crypto-relevant floor of the runtime image.
