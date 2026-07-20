---
title: "Companions — Brief Addendum (technical depth)"
project: smpp-companions
status: final
updated: 2026-07-20
---

# Companions — Brief Addendum

Technical depth that belongs downstream (PRD / architecture), kept out of the brief.

## Tech stack (from brainstorm + brief Discovery)

- **Platform:** JVM — **JDK 25**.
- **Network layer:** **Netty** (latest) — the SMPP wire / async-I/O foundation.
- **Concurrency:** **Virtual threads + `StructuredTaskScope` + `ScopedValue`** (Project Loom) for the control plane; `StructuredTaskScope` is preview-only on JDK 25 (final ~JDK 27), so the build/runtime use **`--enable-preview`** (`ScopedValue` is final). Steady-state byte relay runs on **Netty event loops** (platform threads); virtual threads carry only the control plane.
- **Application substrate:** **Spring Boot 4.1.x** — externalized config (`@ConfigurationProperties`), DI, lifecycle/graceful shutdown, Micrometer. Netty is driven directly (own bootstrap; no WebFlux/Reactor). Not part of the from-scratch SMPP layer.
- **Native-image:** **GraalVM native-image is NOT a v1 build target** (always-on single-instance → startup/footprint gains are noise; ZGC unavailable in native-image). The codebase stays native-image-compatible as a documented stretch. *(Reconciled to architecture AD-23 — supersedes the earlier "escape hatch" framing.)*
- **Originality:** **Built entirely from scratch for JDK 25** — Cloudhopper and jSMPP are *inspirations* (conceptual lineage / ecosystem familiarity for contributors), **not** forked or reused code. No derivation, no licensing/attribution entanglement.
- **Rationale:** modern Java on the JVM (where the SMPP-contributor audience lives) while keeping the form-factor story clean (a standalone application / runnable JAR, with Docker as a packaging of that same JAR).

## Authority provider & certificates (external — not part of Companions)

- **Authority provider = external / BYO.** Companions delegates password-grant validation + mTLS client-cert authn to an authority provider the **operator runs**; it is **not part of the Companions project.** **Keycloak** is the reference/intended provider, but the integration is pluggable.
- **Integration protocol = OIDC.** Companions conforms to OpenID Connect (the standard Keycloak implements) for the password-grant check — no bespoke contract, so any OIDC-compliant provider drops in.
- **Certificates are environmental.** Companions **does not issue certs and is agnostic to who does** — it expects valid certs (server + client) to be **present at runtime**, however the operator provisions them (deploy-time bake, a CA, Vault, etc.). The earlier "deploy-time bake" choice is one valid source, not a mandate.
- **Principle:** Companions is the proxy tier only. The IdP and the PKI are operator-provided infrastructure that exists when the app runs.

## Suite context — the family

**Companions** is a family; v1 is the security-transit companion. Named next siblings (all **from scratch**): a **modern JVM SMPP library** (a successor to Cloudhopper/jSMPP for current Java — likely the shared foundation the others build on; v1's SMPP internals should factor toward it) and a **JMeter load-testing plugin for SMPP**. Earlier candidates (logging/audit, rate-limiting, protocol translation) remain on the table; baseline `/metrics` + operational logging now ship in v1, leaving a fuller metrics/observability companion as a possible future sibling. The v1 architecture should keep a clean, extractable SMPP library core (modularity as code quality — **structured for future extraction**, not a v1 extension-point surface), not a hard-coded single-purpose proxy.

## Architecture (pointer, not re-derivation)

The full security architecture lives in:
`_bmad-output/brainstorming/brainstorm-smpp-security-proxy-2026-07-18/brainstorm-intent.md`

Coverage there: two-proxy topology (`legacy → forward proxy → reverse proxy → SMSC` + direct Mode B); deployment modes A/B/C (one-way TLS / plaintext / mTLS); password-grant forwarded end-to-end (legacy `system_id` == carrier `system_id`); trust consumed from **three roots** — the operator's OIDC authority provider, the operator's PKI / trust store, and the SMSC (sole password authority) *(brainstorm's unified-trust-root — provider == mTLS CA — is relaxed to three roots; user-confirmed in the architecture memlog)*; SMSC stateful (multi-bind under one `system_id`, session-affinity DLRs), reverse proxy stateless relay; forward proxy Mode C uses per-instance baked client certs (rotation = re-deploy).

**Accepted risks** (carried forward): password-only as sole ingress factor; Mode B sends the password plaintext over the public internet; trusted-network assumption on the legacy↔forward-proxy leg; long-lived baked certs forfeit short-lived-cert revocation.

**Open items as of brainstorm** (carried forward as a pointer — revocation, reverse-proxy server-cert provisioning, HA/failover, and bind/PDU audit logging are resolved in the PRD; only the authority-provider↔SMSC relationship remains deliberately pluggable).
