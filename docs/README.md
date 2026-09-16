# Operator Documentation — index

> **Status:** authored with Story 6.1 T4 (2026-09-13) — this index is documentation only, nothing
> in the repository parses it · **Audience:** operators meeting the proxy for the first time, and
> reviewers keeping the pages honest · **Language:** English is the index language; the English
> originals are normative. Russian translations exist for three of the six pages under
> [`ru/`](ru/) — [`a-1-carrier-test-plan.md`](ru/a-1-carrier-test-plan.md),
> [`configuration.md`](ru/configuration.md), and
> [`operator-jvm-flag-contract.md`](ru/operator-jvm-flag-contract.md); the rest are untranslated
> by owner decision (the docs/ru round is a separate later effort).

The proxy is headless — documentation IS the operator surface (OPS-1): no UI, no management API,
no dashboard. Six pages, one fact per home: pages cross-link the owning page instead of
duplicating it (and state what they do NOT cover where a wrong home would mislead), which is
what keeps six pages coherent
when nothing in the repository parses them (owner rule 2026-09-10: no Java test's oracle is a
markdown page — page↔reality coherence is a review-time duty; a change to anything these pages
document goes through a story that touches the code AND the page).

| Page | What it owns |
|---|---|
| [`deployment-guide.md`](deployment-guide.md) | taking an instance from zero to running: per-cell walkthroughs (forward A/C, reverse A/B/C) in both packaged shapes — the JAR launch and the canonical `docker run` recipe — plus the ROPC removal-track disclosure, the verbatim Mode A/B boot banners, the machine-proven matrix, and the packaged-shape conformance run (the composed two-instance journeys, Story 6.2). Start here. |
| [`configuration.md`](configuration.md) | every live `companion.*` key: type, default, fail-fast guard; the AD-17 role×mode matrix; the OIDC policy blocks; the retired keys and the refusals a stale config now gets |
| [`runbooks.md`](runbooks.md) | operating a live instance: the deny-surface table (where each failure surfaces — wire / log / metric), the log-event and `/metrics` references, the `OPERATOR_WARNING` diagnosis flow, shutdown/exit semantics, Mode A ACL isolation, JFR/heap-dump hygiene, troubleshooting |
| [`cipher-allowlist-policy.md`](cipher-allowlist-policy.md) | the `companion.tls.*` posture: the shipped protocol/cipher defaults, the three fail-fast enforcement gates, and the operator tuning envelope |
| [`operator-jvm-flag-contract.md`](operator-jvm-flag-contract.md) | the one JVM launch flag set every packaged launch must carry, the `-XX:MaxDirectMemorySize` ↔ `companion.memory.*` interlock, the documented lazy-initialization deviation |
| [`a-1-carrier-test-plan.md`](a-1-carrier-test-plan.md) | the non-CI real-carrier falsification of assumption A-1 (concurrent binds under one `system_id` + DLR affinity): explicit PASS/FAIL criteria, the assertion procedure, evidence |

Deliberately NOT here: performance numbers (Epic 7's report, Story 7.1, will publish them under
the PERF-070/071 disclosure gates) and the Kannel sandbox rig (Story 6.3 will own its README).
The packaged-shape conformance-run instructions live in the
[deployment guide](deployment-guide.md) (Story 6.2 landed them there). The SMPP 3.4
specification PDF (`SMPP_v3_4_Issue1_2.pdf`) is kept beside these pages as reference material.
