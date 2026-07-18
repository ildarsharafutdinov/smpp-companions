# SMPP 3.4 Security Proxy — Intent

## 1. Intent

Front legacy SMPP 3.4 systems (password-grant bind only, cannot present client certs / cannot do mTLS) in front of carrier SMSCs with a two-proxy security tier that confines the legacy auth weakness to a trusted zone, brokers a single credential end-to-end, and lets the proxy tier ship credential-free. A single converged architecture; three mutually-exclusive deployment modes (A/B/C) cover real-world legacy reach.

## 2. Architecture (landed)

```
Option A / C (proxied):                Option B (direct):

  legacy ──trusted net──> proxy1 ──internet──> proxy2 ──trusted net──> SMSC
            (no TLS)        (TLS or mTLS)        (no TLS)         (password-grant)
                                                  ^
                                                  │
  legacy ──────────── internet (plaintext) ───────┘
                   (Option B only)
```

Per-leg:
- **legacy ↔ proxy1** — trusted network, no TLS, no authn by proxy1. Proxy1 does NOT validate the legacy password; it reads `system_id` from the bind PDU and routes on it. The trusted network is the sole ingress gate on this leg.
- **proxy1 ↔ proxy2 (internet leg)** — mode-dependent (see §5). proxy2 terminates TLS in all modes.
- **proxy2 ↔ SMSC** — trusted network, no TLS, SMPP password-grant bind with carrier-issued creds. Legacy `system_id` == carrier `system_id` (end-to-end identity; no pooled/mapped identity).
- **legacy ↔ proxy2 (Option B only)** — public internet, plaintext SMPP, password-grant only.

Proxy1 = stateless routing tier (read `system_id` → pick per-carrier proxy2). Proxy2 = stateless relay/splice (socket pairing only; no business/message state).

## 3. Authentication & trust model

- SMPP password-grant forwarded end-to-end: **legacy `system_id` == carrier `system_id`**. SMSC is the credential authority.
- Proxy2 delegates the grant check to an **AUTHORITY PROVIDER** (external auth/IdP). No local password storage, no local brute-force policy on proxy2.
- The authority provider is **also the CA for the mTLS client certs** → **unified trust root** for both password-grant validation and mTLS. In Option C both ingress factors chain to the same provider.
- Proxy2 is credential-free: holds only TLS certs + provider-call creds. The trust crown jewel migrates **off proxy2 onto the authority provider** — compromise of the provider = mint valid client certs + approve any grant = full impersonation (protect + make HA).
- Proxy2 is **agnostic** to the authority-provider ↔ SMSC relationship (shared AAA vs independent validator). That sync is the deployer's concern, not the proxy's. proxy2 contract: delegate the grant, trust the verdict.

## 4. Data flow / DLRs

- Traffic is **MT-only** (legacy → carrier). No MO/inbound user messages.
- DLRs return on the existing binds (transceiver/receiver), not a separate path.
- SMSC is stateful: owns message state and routes DLRs back by **session-affinity**.
- Each legacy bind gets its own spliced upstream session under the shared `system_id`; SMSC supports **multiple concurrent binds under one system_id** (assumption to verify, §9).
- Proxy2 holds only socket-pairing/connection state — no `message_id → system_id` correlation. This keeps HA simple (no in-flight message state to lose).

## 5. Deployment modes (A/B/C)

Single mutually-exclusive deployment-wide choice (product ships all three topologies; each instance runs exactly one). **Not** a per-client tiered menu.

- **Mode A — one-way TLS internet leg:** proxy1 validates proxy2's server cert; proxy1 presents **no** client cert. Revised down from mTLS.
- **Mode B — plaintext direct:** legacy → proxy2 over public internet, no TLS, no mTLS, password-grant only. The legacy-can't-TLS direct case.
- **Mode C — mTLS internet leg:** proxy1 presents a client cert so proxy2 cryptographically authenticates the proxy1 endpoint (closes the "can't tell real-proxy1 from attacker-with-stolen-password" gap). SMSC auth stays password-grant.

Security order: **C > A > B**. Open product question: ship all three modes incl. plaintext B and let the customer own that risk, or enforce a security floor (refuse to start in B)?

## 6. Certificate provisioning

- Proxy1's mTLS client cert (Option C) = **deploy-time bake** (provisioned at deploy by CI/pipeline; no ACME/SPIFFE/sidecar; rotation = re-deploy). Bootstrap handled out-of-band by the bake pipeline's own credential.
- Consequence: long-lived certs → **forfeits** the "short-lived dissolves revocation" property. Revocation (CRL/OCSP) is reinstated as a real need, or accept the long exposure window of a stolen baked cert.
- Proxy2 server cert provisioning: open (§9).

## 7. Key decisions & rationale

- **Two-proxy split** confines L2 (legacy can't do mTLS) to the trusted zone; turns the per-carrier credential problem into a single concentrator per carrier.
- **Forward-as-is password grant** (legacy `system_id` == carrier `system_id`) makes proxies credential-free transparent relays — no password vault anywhere in the proxy tier; SMSC is the sole credential authority. Low blast radius: proxy compromise yields position, not a stash of working passwords.
- **Auth delegated to authority provider** restores proxy2 credential-free status without losing pre-filter / brute-force protection; keeps the three-way credential-sync problem (legacy ↔ proxy2 ↔ SMSC) out of the proxy by making the provider↔SMSC relationship the deployer's concern.
- **Unified trust root** (provider = password validator + mTLS CA): in Option C both ingress factors chain to one thing.
- **Single deployment-wide mode** (not per-client tiered) — operational simplicity.
- **Deploy-time bake over ACME/SPIFFE** — simplicity/legacy-constraint wins.
- **Disproved constraints:** carriers do NOT mandate TLS/mTLS (C1=no) → upstream TLS is our choice.

## 8. Accepted risks (explicit, deliberate)

- **Password-only** is the sole authn factor reaching proxy2 in both internet-ingress modes (A and B). Declined second-factor (mTLS-in-A, VPN/IPSec for direct legacy) — simplicity wins.
- **Option B sends the legacy password plaintext over the public internet.**
- **Trusted-network assumption** is the only ingress gate on the legacy↔proxy1 leg; proxy1 routes on an unauthenticated `system_id`, so any host on that net can claim any `system_id` and be steered toward any carrier's proxy2 before any check.
- **Long-lived baked certs** forfeit the short-lived-certs-dissolve-revocation property; a stolen baked cert is valid until expiry unless revocation infra exists.
- **Provider outage = no new binds succeed** (HA coupling); ongoing mTLS survives on cached trust store but grant validation and cert issuance/revocation need the provider live. Bind latency += provider round-trip (acceptable; binds infrequent/long-lived).

## 9. Open items & assumptions to verify

**Should (recommended, uncommitted):**
- Revocation (CRL/OCSP) **OR** scheduled re-bake (7–30d lifetime, automated re-deploy pipeline) for baked certs.
- Protect the baked key: **per-instance keys**, not one shared golden-image key; lock down bake pipeline + image distribution; key storage on proxy1 (file perms / sealed secret).
- Proxy2 server-cert provisioning (lifecycle unspecified).
- Audit/logging of binds + PDUs (granularity open).

**Could (optional):**
- mTLS on the Option-A leg too (i.e., converge A toward C).
- Rate-limit / anomaly detection at proxy2.
- Full pre-mortem (Lens 4) on the authority provider.

**Won't-this-time (declined):**
- Per-client carrier identity (pooled/proxy2-as-self identity only).
- Proxy1-side credential validation.
- MO/inbound support (MT-only).
- ACME/SPIFFE runtime enrollment.
- Short-lived-cert auto-rotation.

**Assumptions to verify:**
- Carrier allows **multiple concurrent binds under one system_id** (drives the stateless splice model; if carrier allows only one bind, proxy2 is forced back to `message_id` correlation → stateful).
- **Authority-provider ↔ SMSC relationship** is deliberately unspecified/pluggable — sync between them (if any) is the deployer's concern.
- **Proxy2 → authority-provider link** security (TLS/mTLS/token/service acct) — parked.
- Carrier-credential store choice (local vs Vault/KMS) — open cell.
- HA/failover design (simplified by stateless proxy2 but not specified).
