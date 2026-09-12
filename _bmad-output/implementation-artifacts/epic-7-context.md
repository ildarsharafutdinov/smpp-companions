# Epic 7 Context: Validate all performance — the measurement harness and the published evidence

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->
<!-- Compiled 2026-09-12 (the Epic 6/7 split, owner direction same date): the former Epic 6's performance half
     becomes its own epic — "epic 7 focuses on performance measurement" — carrying the 31-row PERF catalog
     area (zero landed), the [B]-topology consequence for PERF-1's "mTLS both legs" anchor, and the AD-30
     interlock bounding the idle demo. Story 7.1 was created as 6.1 before the split and renumbered in place
     (baseline unchanged, 2f2b0e8). -->

## Goal

Prove every locked performance bet with published, reproducible evidence — a no-crypto baseline that
attributes relay cost vs. crypto cost, the final throughput/latency numbers (≥10,000 `submit_sm`/sec,
stretch ~25K, with a p50/p90/p99/p99.9 percentile table and the saturation knee + failure modes), 10,000
idle socket pairs in <1 GB heap / <1 vCPU, sub-ms per-PDU relay latency, codec JMH bands — all measured on
the PACKAGED shapes Epic 5 shipped, published under the disclosure/report gates (PERF-070/071). NFR-driven:
no FRs. The methodology IS the bar (SM-3, readiness report :178): every number self-measured, labeled, and
disclosed; PERF-1..4 are first-of-kind with no published JVM-SMPP-proxy reference (AD-24(5) scopes the
"first-of-kind" claim to "no published SMPP proxy/stateless-relay benchmark"). Status: Epics 1–5 done
(`2f2b0e8`); independent of Epic 6 (may run before/after/in parallel — the only coupling is that Epic 7
authors the perf-report page itself).

## Stories

- 7.1 — performance-validation harness + published evidence: the open-model load rig (coordinated-omission-proven),
  the throughput/percentile/knee numbers on the no-crypto baseline and the mTLS-heaviest cell, the 10K-idle-pairs
  demo, the bind-latency cluster (incl. real-Keycloak bind-rate), the GC/blocking/shutdown-under-load slices,
  the codec JMH band publication, and the perf-report page. Catalog area: PERF-010..021/030..034/040/050..052/
  060..061/070..071 + the PERF-001..005 publication arms.

## Requirements & Constraints

- **The methodology is the deliverable, not the peak:** no sustained number publishes without its percentile
  table (PERF-011), saturation knee + failure modes (PERF-016/071), and full environment disclosure (PERF-070 —
  payload, cipher, single-instance, HW/JDK/reboot/sysctl). Mock-IdP bind-rate is regression-only, never the
  published ceiling (PERF-034).
- **[B]-topology constraint on PERF-1's "mTLS both legs" (pre-[B] anchor text):** post-[B] (AD-20 amendment,
  2026-08-21) the SMSC leg is always plaintext and each instance owns exactly ONE TLS transit leg (the forward
  dials it, the reverse listens on it; Mode C adds client certs there). The published mTLS number is measured
  on the Mode-C cell; the no-crypto baseline (PERF-013) isolates crypto cost. An end-to-end both-hops-TLS
  number, if wanted, is the composed two-instance chain — Epic 6 territory.
- **The AD-30 interlock bounds the idle demo:** PERF-020's 10K pairs exceeds the default
  `companion.memory.concurrent-pairs: 1024` cap AND its derived budget (64 KiB × depth × pairs × 1.5) exceeds
  the contract's pinned 6 GiB `MaxDirectMemorySize` — the demo runs with disclosed, coherently-scaled arg
  overrides (per the contract page's floor+mirror rule), recorded in the report's disclosure.
- **Honest exception (epics.md):** if final validation exposes a genuine hot-path defect, the fix returns to
  the owning epic (relay/ Epic 2 refactors, codec/ Epic 1), never patched inside the harness.
- **The perf harness lives in `proxy/src/test/`** (AD-24(2): the in-JVM mock SMSC on `codec` is the A-1
  fixture + PERF sink). The JMH bench already lives in `proxy/src/jmh` (Story 1.2 T7; nightly-tier,
  deliberately outside `build`/`check`).
- **No CI exists** (owner 2026-09-11); the report gates are repo-local, not CI gates, until release tooling
  ever lands.

## Technical Decisions

- **The measured shape is the packaged JAR** (subprocess `java -jar proxy.jar` under the operator flag set —
  the thing operators run; Epic-5's handoff says formal validation runs on the packaged shapes). The Docker
  image is parity-proven structurally (one jar, one arg channel) — no Docker perf matrix in this epic unless
  the owner asks.
- **PERF-015 semantics:** "OIDC validation cached" = JWKS-era stand-in warms pre-window; the VERDICT is never
  cached (AD-12, each bind re-adjudicates — SEC-094 pins it); binds establish BEFORE the measurement window;
  bind-rate is a separate reported column.
- **Percentile recording:** no HdrHistogram/latency-utils dependency exists anywhere today — the recorder
  choice (HdrHistogram vs. hand-rolled) is a 7.1 T1 decision through the dependency-floors lane
  (`smpp.dependency-floors`).
- **BlockHound (PERF-060) JDK-25 support is unverified** (instrumentation agents historically lag new JDKs) —
  the row carries a JFR-based fallback disposition if the agent cannot ride JDK 25.
- **The `-prof gc` wiring (PERF-004)** is a standing 1.2-T7 defer (one-shot manual measurement was reverted);
  7.1's T6 owns the re-wire decision (profilers config vs. documented invocation).

## Cross-Story Dependencies

- **Depends on Epic 5 (done):** both packaged shapes, the operator flag contract (`docs/operator-jvm-flag-contract.md`
  — the floor+mirror rule the idle-demo overrides ride), the packaged-smoke SIGTERM/scrape idioms.
- **Independent of Epic 6** (the Kannel sandbox, composed conformance, and docs surface): neither blocks the
  other; Epic 7 authors its own perf-report page, so the docs epic never waits on numbers.
- The test-design catalog's PERF area (31 rows, none landed) is the AC-level source for 7.1.
