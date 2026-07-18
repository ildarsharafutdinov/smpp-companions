# Companions — Brief Addendum

Technical depth that belongs downstream (PRD / architecture), kept out of the brief.

## Tech stack (from brainstorm + brief Discovery)

- **Platform:** JVM — **JDK 25**.
- **Network layer:** **Netty** (latest) — the SMPP wire / async-I/O foundation.
- **Concurrency:** **Virtual threads + structured concurrency** (Project Loom), where applicable.
- **Performance escape hatch:** **GraalVM native-image** (AOT) if performance or footprint demands it.
- **Originality:** **Built entirely from scratch for JDK 25** — Cloudhopper and jSMPP are *inspirations* (conceptual lineage / ecosystem familiarity for contributors), **not** forked or reused code. No derivation, no licensing/attribution entanglement.
- **Rationale:** modern Java on the JVM (where the SMPP-contributor audience lives) while keeping the library-vs-container story clean (library core, thin Docker wrapper).

## Authority provider & certificates (external — not part of Companions)

- **Authority provider = external / BYO.** Companions delegates password-grant validation + mTLS client-cert authn to an authority provider the **operator runs**; it is **not part of the Companions project.** **Keycloak** is the reference/intended provider, but the integration is pluggable.
- **Integration protocol = OIDC.** Companions conforms to OpenID Connect (the standard Keycloak implements) for the password-grant check — no bespoke contract, so any OIDC-compliant provider drops in.
- **Certificates are environmental.** Companions **does not issue certs and is agnostic to who does** — it expects valid certs (server + client) to be **present at runtime**, however the operator provisions them (deploy-time bake, a CA, Vault, etc.). The earlier "deploy-time bake" choice is one valid source, not a mandate.
- **Principle:** Companions is the proxy tier only. The IdP and the PKI are operator-provided infrastructure that exists when the app runs.

## Suite context — the family

**Companions** is a family; v1 is the security-transit companion. Named next siblings (all **from scratch**): a **modern JVM SMPP library** (a successor to Cloudhopper/jSMPP for current Java — likely the shared foundation the others build on; v1's SMPP internals should factor toward it) and a **JMeter load-testing plugin for SMPP**. Earlier candidates (logging/audit, rate-limiting, protocol translation, metrics/observability) remain on the table. The v1 architecture should keep companions as **pluggable modules** with a clean SMPP library core, not a hard-coded single-purpose proxy.

## Architecture (pointer, not re-derivation)

The full security architecture lives in:
`_bmad-output/brainstorming/brainstorm-smpp-security-proxy-2026-07-18/brainstorm-intent.md`

Coverage there: two-proxy topology (`legacy → proxy1 → proxy2 → SMSC` + direct Option B); deployment modes A/B/C (one-way TLS / plaintext / mTLS); password-grant forwarded end-to-end (legacy `system_id` == carrier `system_id`); auth delegated to an **authority provider** that is also the **mTLS CA** (unified trust root); SMSC stateful (multi-bind under one `system_id`, session-affinity DLRs), proxy2 stateless relay; proxy1 mTLS client cert via deploy-time bake.

**Accepted risks** (carried forward): password-only as sole ingress factor; Option B sends the password plaintext over the public internet; trusted-network assumption on the legacy↔proxy1 leg; long-lived baked certs forfeit short-lived-cert revocation.

**Open items** (carried forward): revocation (CRL/OCSP) vs scheduled re-bake; proxy2 server-cert provisioning; HA/failover; bind/PDU audit logging; authority-provider↔SMSC relationship (deliberately pluggable).
