# Operator JVM-Flag Contract — the one launch flag set (JAR + Docker shapes)

> **Status:** ratified with Story 5.1 (2026-09-10; amended same day); extended to the Docker shape
> with Story 5.2 (2026-09-12) — this page is documentation only, nothing in the repository parses
> it · **Audience:** operators launching the packaged proxy, by `java -jar` or `docker run` ·
> **Owner decision:** bare `java -jar` and the image's exec-form ENTRYPOINT + this page — no
> launcher script in the repository, and no launch configuration travels in the jar manifest.

This page is the **operator-facing definition** of the JVM flags every packaged launch must carry
(FR-DEPLOY-1). The packaged boot+smoke test (Story 5.1 T5) launches the jar with exactly this set,
defined as a Java-side constant in the test source — by owner rule (2026-09-10) no code or test
reads this page, so keeping page and constant in step is a review-time duty: a flag change goes
through a story that touches both. The Docker image's exec-form ENTRYPOINT (Story 5.2 T2) carries
the same set verbatim — neither deploy shape authors its own flags, so the two shapes cannot
drift, and a Testcontainers parity row asserts constant ↔ ENTRYPOINT exactly.

The launch presumes the pinned JDK 25 build (`java temurin-25.0.3+9.0.LTS`, `.tool-versions`):
preview semantics ride on the exact build, which is pinned by the **environment** (asdf
`.tool-versions`), not by the build — the Gradle toolchain pins major 25 only, and there is
deliberately no build-time version check (owner decision, 2026-09-10: "asdf pin is enough, no
additional jdk/jre version check is needed"). Flags go **before** `-jar`; anything after the jar
path is ordinary Spring/cell configuration (args or env), not part of this contract.

## The pinned set

```text
java --enable-preview -XX:+UseZGC -XX:MaxDirectMemorySize=6442450944 -Djava.net.preferIPv4Stack=true -jar proxy.jar
```

This is a **minimum set**: every launch must carry all four flags. If you add any further JVM flag
(heap sizing — `-Xmx`/`-XX:SoftMaxHeapSize`, GC tuning, …), the SAME addition must ride BOTH deploy
shapes — this JAR launch and the Docker ENTRYPOINT — or be added to neither:
per-deploy-shape flag divergence is exactly the drift FR-DEPLOY-1 forbids, and the obvious next
knob (heap sizing on a ZGC instance) is precisely the one that would silently fork the shapes.

The artifacts, one per shape:

- **JAR:** `proxy/build/libs/proxy.jar`, built by `./gradlew :proxy:bootJar` (the version-free name
  is pinned; the version travels inside the manifest).
- **Docker image:** built by `./gradlew :proxy:dockerImage` (tag `smpp-proxy:local`) from
  `proxy/src/docker/Dockerfile` — distroless `base-debian12:nonroot`, packaging that SAME jar
  byte-for-byte (never rebuilt) over the jlink runtime `:proxy:jlinkRuntimeImage` derives from it
  (jdeps module set + the crypto floor). The exec-form ENTRYPOINT is
  `["/opt/jre/bin/java", <the four flags above>, "-jar", "/opt/proxy.jar"]` with an empty `CMD`:
  arguments after the image name append as ordinary Spring run args, exactly like arguments after
  the jar path in the JAR shape.

## Why each flag

**`--enable-preview` — load-bearing.** The proxy's classes are compiled with JDK 25 preview
features (JEP 505 `StructuredTaskScope`, spine AD-5 — the bind-adjudication path runs on it), and
this flag is the **single load-bearing preview mechanism** for the packaged shape: the jar manifest
deliberately carries no preview marking, because the `Enable-Preview` attribute was proven inert on
the pinned launcher (temurin 25.0.3+9 reads Add-Exports/Add-Opens/Enable-Native-Access from
manifests but has no `Enable-Preview` arm) and was dropped by owner amendment on 2026-09-10. A
launch without the flag does not degrade — it refuses outright: `UnsupportedClassVersionError`,
naming `--enable-preview`, at the first preview-marked class. Fail-closed by construction.

**`-XX:+UseZGC`** — the pinned collector for this deployment shape: an always-on, latency-sensitive
single instance. Both packaged shapes are smoke-tested shapes, and both are smoke-tested on ZGC;
omitting the flag leaves the JVM-default collector — an untested GC posture, and a GC divergence
between the two shapes, exactly what the one-flag-set rule exists to prevent.

**`-XX:MaxDirectMemorySize=6442450944`** — the AD-30 direct-memory budget. Netty allocates every
SMPP PDU buffer off-heap; without an explicit cap the direct budget is effectively unbounded and
the process OOMs at scale instead of degrading. The value is not free-standing — it is exactly the
shipped `application.yml` default derivation:

> 65536 × 64 × 1024 × 1.5 = 6,442,450,944 bytes (6 GiB)

where 65536 is the codec max frame (`SmppFrame.MAX_COMMAND_LENGTH`, the fixed formula input) and
64 / 1024 / 1.5 are the shipped `companion.memory` trio — `max-inbound-depth`, `concurrent-pairs`,
`safety-factor`. At boot the AD-30 self-check compares the yml-derived budget against this live
ceiling under `companion.memory.budget-check: fail`: an over-budget launch **refuses startup**
(AD-17 fail-fast), it never warns-and-continues. Consequence for operators: if you retune the
`companion.memory` trio, retune this flag to at least the new derived budget
(65536 × depth × pairs × factor), or the boot refuses.

**`-Djava.net.preferIPv4Stack=true`** — the proxy is IPv4-only (COMP-4): the read-only `/metrics`
listener binds the `127.0.0.1` literal, and egress — to the SMSC and to the IdP — must connect over
IPv4 even when a hostname resolves AAAA records too. The system property makes the JDK prefer the
IPv4 stack, so a dual-stack host cannot silently yield IPv6 sockets on either leg.

## Lazy initialization — documented deviation, no runtime guard

`spring.main.lazy-initialization=true` is **not refused** at startup. By owner decision (2026-09-10)
there is **no runtime guard**: the flag ships live and the warning lives here, on this page.
Enabling it defers the proxy's fail-fast posture from boot to **first use** — specifically, the
**AD-17** role×mode startup-validation matrix and the **AD-30** direct-memory budget self-check run
lazily, when the first affected bean is touched, instead of at launch. A misconfigured or
under-provisioned instance therefore boots green and surfaces its refusal at the first bind (or
first scrape), not at startup. Operators who enable lazy-initialization accept this deviation
knowingly; the shipped default (no flag) keeps validation at boot, where the fail-closed posture
lives.

## How the set is kept coherent

Three kept-in-step representations of the ONE set:

- **Packaged boot+smoke** (Story 5.1 T5): launches the built jar as a subprocess with exactly the
  set above, from a Java-side launch constant in the test source (`PackagedBootSmokeTest.OPERATOR_JVM_FLAGS`)
  — the executable definition of the JAR shape.
- **The Docker ENTRYPOINT** (Story 5.2 T2, `proxy/src/docker/Dockerfile`): launches the same JAR
  with the same set, exec-form, as the image's only launch definition. Its parity with the constant
  is pinned by a Testcontainers row (`DockerImageBootSmokeTest.imageEntrypointCarriesTheContractFlagSetVerbatim`
  — `docker inspect` ENTRYPOINT ≡ `[/opt/jre/bin/java]` + `OPERATOR_JVM_FLAGS` + `[-jar, /opt/proxy.jar]`,
  plus no env flag-fork via `JDK_JAVA_OPTIONS`/`JAVA_TOOL_OPTIONS`/`JAVA_OPTS`/`_JAVA_OPTIONS`).
- **This page**: the operator reference. By owner decision (2026-09-10) nothing in the repository
  parses it — no test, no launcher — so a flag change is a story that touches the constant, the
  ENTRYPOINT, AND this page, and the reviewer checks all three match (the constant ↔ ENTRYPOINT
  half is machine-checked; page coherence is the review duty).
