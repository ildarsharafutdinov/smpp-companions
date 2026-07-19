---
title: "Companions (v1: SMPP Security-Transit Companion)"
project: smpp-companions
status: final
created: 2026-07-18
updated: 2026-07-19
inputs:
  - _bmad-output/brainstorming/brainstorm-smpp-security-proxy-2026-07-18/brainstorm-intent.md
---

# Companions — Product Brief (v1: the SMPP Security-Transit Companion)

> OSS pet project. Lean brief — no investor rigor. **"Companions" is a *family*** of non-invasive augmentation modules for legacy SMPP; this brief covers the first one — secure transit.

## The itch (why this exists)

A legacy SMPP system needs modern capabilities — **security first** (TLS, stronger authentication) — but **can't be modified.** It speaks SMPP 3.4 with password-grant binds and no real transport security, and must talk to a carrier over the internet. That constraint isn't negotiable: the legacy system stays exactly as it is. The only option is an **external layer** that absorbs the legacy traffic and adds the missing capabilities without touching it.

The real itch is the **pattern**: *bolt modern features onto untouchable legacy.* Security is the first feature set; it won't be the last — which is why the project is **Companions**, plural: a family of small, non-invasive modules that each add one modern capability to a legacy SMPP system that can't get it any other way.

## What it is (v1: the security-transit companion)

The first **Companion** is an open-source **SMPP security proxy** that sits in front of legacy SMPP 3.4 systems *and* in front of carrier SMSCs, letting the two exchange SMPP **securely over the internet, with zero changes to the legacy gear.**

- **Headless middleware** — no UI; operator-configured.
- **Two deployment shapes, both first-class:** a standalone **application (runnable JAR)**, or a **Docker image** (which packages that JAR).
- **Both sides of the wire:** one tool plays the **enterprise/ingress** role (fronting a legacy system connecting to a carrier) *and* the **carrier/egress** role (fronting an SMSC accepting connections). One codebase, two roles.
- **Modern JVM stack** (JDK 25, Netty, virtual threads / structured concurrency; GraalVM native-image if perf demands it) — **inspired by** Cloudhopper and jSMPP, **built entirely from scratch for JDK 25** (not a fork, no reuse of their code). *(Stack specifics → addendum.)*
- **Consumes external trust, doesn't provide it** — auth delegates to an authority provider the operator runs **over OIDC** (the standard Keycloak implements, so any OIDC provider drops in — no bespoke contract); **Keycloak is the reference target, not part of this project.** Certificates are expected **present at runtime, source-agnostic**. Companions is the proxy; the IdP and the PKI live in your environment.

## The core idea

A legacy SMPP system and a carrier SMSC that could never safely talk over the public internet can do so through a pair of these proxies: each party runs one, the proxies carry the security (TLS/mTLS, OIDC-backed authentication), and the legacy systems on both ends stay unchanged. The companion **augments without altering** — and because it's the first of a planned family, the same non-invasive pattern can later deliver other capabilities (logging/audit, rate-limiting, protocol translation…) to the same untouchable legacy.

*(Full security architecture — two-proxy topology, per-leg TLS, authority-provider auth model, DLR handling — is in `brainstorm-intent.md` and flows to the PRD/architecture. The brief deliberately stays on what & why, not how.)*

## Who it's for

- **Enterprises / ESMEs** with legacy SMPP stacks that must reach carriers over the internet and can't modernize the legacy code.
- **Carriers / SMSC operators** accepting binds who want to harden ingress without forcing clients off SMPP 3.4.
- **The author** — see *Success*.

## Scope (v1)

**In:** SMPP **3.4**, **payload-transparent transit** — carries traffic end-to-end without inspecting or filtering message content (the motivating use case is MT submit + DLRs on existing binds, but no message-type filter is enforced); the three deployment modes (A/B/C); password-grant + mTLS; **authority-provider integration over OIDC (BYO; Keycloak reference)**; **runtime-provided certificates (source-agnostic)**; application (runnable JAR) + Docker shapes.

**Out / non-goals (v1):** no UI; **no SMPP 5.x**; **no inspection, filtering, or routing based on message content or type** (the proxy is payload-transparent — MT-only is the expected deployment, not a proxy-enforced filter); **no management API, no metrics *dashboard* / telemetry backend** (a read-only `/metrics` scrape + baseline logging *are* provided); **Linux only (no macOS/Windows build)**; **no bundled authority provider / no cert issuance** (the IdP and PKI are the operator's). (Future companions may pick some of these up.)

## What "win" looks like

A **portfolio piece** — original, from-scratch work. Success = a real, well-built, shippable OSS project that demonstrates modern Java (concurrency, networking) applied to a genuine security problem — something the author is proud to show, actually uses to scratch the original itch, and that establishes the *Companions* pattern for the next module. Community adoption is a bonus, not the goal.

## Inspiration & positioning

**Cloudhopper** and **jSMPP** are the **inspirations** — the established JVM SMPP libraries that proved the shape and the demand — but Companions is **built entirely from scratch for JDK 25** (not a fork, not derived from their code): current JDK, Loom-era concurrency, and a *security-proxy* shape they weren't. Not a general SMPP library — the **secure-transit companion** for systems that already speak SMPP, and the seed of a small family of such companions.

## The family (what's next)

v1 is the security-transit companion. Planned siblings, all **from scratch** on the same modern-JVM stack:

- A **modern JVM SMPP library** — a from-scratch successor to Cloudhopper/jSMPP for current Java, and likely the shared foundation the other companions build on (v1's SMPP internals should factor toward it).
- A **JMeter load-testing plugin for SMPP** — serving the SMS-dev / QA community.

Earlier candidate companions — logging/audit, rate-limiting, protocol translation — remain on the table. The v1 architecture stays **modular** so siblings slot in alongside the security companion rather than getting bolted onto a single-purpose proxy.

## Open questions

_All resolved during Discovery:_

- **Keycloak scope** → external / BYO; not part of the project.
- **Certificate issuance** → environmental / source-agnostic; Companions neither issues nor cares.
- **Authority-provider contract** → **OIDC** (the standard Keycloak implements); no bespoke interface.
