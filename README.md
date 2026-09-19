# smpp-companions

An open-source **SMPP 3.4 security-transit proxy**. It sits between your SMS clients (ESMEs)
and the SMSC, so every bind and message crosses one controlled, observable point instead of
reaching the SMSC directly. Built on Netty and Spring Boot 4 (JDK 25): headless,
operator-configured, fail-closed — bad configuration refuses at boot, not in production.

## What is it for?

- **Central credential adjudication** — every SMPP bind's password is verified at your IdP
  (OIDC resource-owner password grant) before the proxy connects to the SMSC.
- **Legacy clients stay untouched** — ESMEs that speak plain SMPP keep working; the proxy
  takes over the security of everything behind them.
- **Transit security in three shapes** — Mode B (plain password), Mode A (one-way TLS between proxy
  tiers), Mode C (mutual TLS) — plus structured JSON logs and a read-only `/metrics` endpoint.

## Modules

| Module | What it is | Status |
|--------|------------|--------|
| [`codec/`](codec/) | The SMPP 3.4 protocol library — a pure, Netty-based encoder/decoder | in development — ships inside the proxy, not yet a standalone release |
| [`proxy/`](proxy/) | The proxy itself — runnable JAR + distroless Docker image | **WIP** |
| jmeter plugin *(planned)* | A JMeter load-testing plugin for SMPP | planned — not started |
| [`sandbox/`](sandbox/) | The dockerized Kannel + Keycloak test rig — a real third-party SMPP stack wrapped around the proxy | **WIP** |
| [`docs/`](docs/) | Operator documentation — configuration reference, deployment guide, runbooks | maintained |

## Try it

The fastest way to see the proxy working is the sandbox. Each use case (role + mode) has its
own step-by-step runbook — build, start the rig, launch the proxy, and watch a real Kannel
chain couple through it:

- **[`reverse`, Mode B](sandbox/runbooks/reverse-mode-b.md)** — legacy clients connect straight
  to a single proxy instance with a plain password; every bind is adjudicated at your IdP.
- **[`forward` + `reverse`, Mode A](sandbox/runbooks/forward-reverse-mode-a.md)** — two proxy
  instances: a plain-password trusted leg, then one-way TLS across the untrusted stretch.
- **[`forward` + `reverse`, Mode C](sandbox/runbooks/forward-reverse-mode-c.md)** — the same
  two hops with mutual TLS between the proxies; the TLS handshake itself is the gate.
- **[sandbox/README.md](sandbox/README.md) — the sandbox in depth.** What the rig is, how to
  bring it up, the correctness journeys, and the debugging guide.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

Русский перевод: [`README.ru.md`](README.ru.md).
