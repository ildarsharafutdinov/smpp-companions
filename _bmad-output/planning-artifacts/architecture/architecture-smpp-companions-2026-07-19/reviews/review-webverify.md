# Web-Verification Review — Companions v1 Architecture Spine

- **Reviewer:** WEB-VERIFICATION (web-reality-check layer of the reviewer gate)
- **Date verified:** 2026-07-19
- **Scope:** every committed tech/version in the spine's `Stack` table (ARCHITECTURE-SPINE.md §Stack, lines 221–237) plus the load-bearing version rationale captured in `.memlog.md` (lines 31–33, 46) that the spine inherits.
- **Method:** each claim checked against primary sources (vendor release notes, Maven Central / Sonatype, NVD, OpenJDK JEPs) as of 2026-07. Versions are confirmed real, current, and fit-for-stated-use unless flagged.
- **Verdict:** **PASS-WITH-FINDINGS.** Every committed version exists, is current (as of 2026-07), and fits the stated use. One inherited rationale claim ("Netty 5 DEAD/abandoned") is factually wrong; it does not change the version pin but should be corrected so the rationale does not undermine the artifact in a portfolio/security review. Two low-severity precision/staleness notes.

---

## 1. Verified-accurate table

| Spine claim | Verified against | Result |
| --- | --- | --- |
| **JDK 25 LTS** (pin build 25.0.x) | Oracle released JDK 25 on **2025-09-16** as the LTS after JDK 21; LTS support to ≥2033; 2-year LTS cadence. 25.0.1 followed 2025-10-21. | ✅ Accurate — LTS confirmed. |
| **Netty 4.2.16.Final via `netty-bom`** | Released **2026-07-07**; it is the current 4.2.x patch and **includes the fix** for GHSA-6mjq-h674-j845 (`netty-handler` `SniHandler` 16 MB allocation, fixed in 4.1.136.Final / 4.2.16.Final). 4.2 has been GA since 2025-04-03. | ✅ Accurate & current; CVE-clean. |
| **4.2 IoHandler API** | Real: `IoHandler` is Netty 4.2's transport SPI (`EpollIoHandler`, `NioIoHandler`, `IoUringIoHandler`); `MultiThreadIoEventLoopGroup(NioIoHandler.newFactory())` is the documented replacement for the deprecated `NioEventLoopGroup`. | ✅ Accurate. (Precision note in §3 — IoHandler is the *transport* SPI, not a replacement for the app-level `ChannelHandler` pipeline the spine also correctly uses.) |
| **NIO/Epoll, NOT io_uring** | Consistent with the memlog's Java-25 event-loop-group shutdown regression (issue #16174) as the reason to exclude io_uring. | ✅ Defensible. |
| **Spring Boot 4.1.x (Spring Framework 7.0.8+)** | Boot 4.1 released **2026-06-10**; Spring docs system-requirements page states Boot 4.1.0 requires **Spring Framework ≥ 7.0.8** and supports Java up to and including 26. Built on Spring Framework 7. | ✅ Accurate; the "7.0.8+" floor is the real documented floor. |
| **Spring Boot 4 — Java 25 first-class** | Multiple 2026 sources recommend Boot 4.1 + Java 25 together; Framework 7 keeps JDK 17 baseline while embracing JDK 25. | ✅ Accurate. |
| **Micrometer ships with Spring Boot 4** | Micrometer has been the default metrics facade since Boot 2.0 and continues through Boot 4.x (2026); `spring-boot-micrometer-metrics` starter active through mid-2026. | ✅ Accurate. |
| **Nimbus JOSE+JWT 10.9.1 (≥10.0.2 for CVE-2025-53864)** | `com.nimbusds:nimbus-jose-jwt:10.9.1` published **2026-05-31** on Maven Central / deps.dev. NVD CVE-2025-53864 affects **10.0.x < 10.0.2** and **9.37.x < 9.37.4** (DoS); 10.9.1 is far above the patched range. | ✅ Accurate; version exists and is CVE-clear. |
| **jSMPP `org.jsmpp:jsmpp:3.0.2` (not 2.3.11)** | `org.jsmpp:jsmpp:3.0.2` is on Maven Central / Sonatype; 3.0.2 is the newer line vs 3.0.1; repo `opentelecoms-org/jsmpp`. | ✅ Accurate. Steer-away from 2.3.11 is correct. |
| **GraalVM for JDK 25 (Oracle 25.1.3 / CE 25.0.2) — stretch only** | **Oracle GraalVM 25.1.3** is listed on Oracle's download hub as current (Innovation release train, LTS to 2030-09-30). **GraalVM CE 25.0.2** (2026-01-20 CPU) is on graalvm.org release notes. | ✅ Accurate. (Staleness note in §3 — CE patch pin may lag July 2026; non-load-bearing.) |
| **Generational ZGC = only ZGC mode in JDK 25** | JEP 439 (gen-ZGC, JDK 21) → JEP 474 (gen by default + deprecate non-gen, JDK 23) → non-gen mode **removed in JDK 24**, `ZGenerational` flag gone. JDK 25 is the **first LTS with generational-only ZGC**. | ✅ Accurate. |
| **Reference IdP: Keycloak 26.x** | 26.0.0 GA 2024-10 → 26.4.0 2025-09 → **26.7.0 2026-07-09**. 26.7 is real and current. | ✅ Accurate. |
| **Keycloak 26.2 = Direct Access Grants non-default** | 26.2.0 release notes (2025-04) list issue **#30226** "Admin-UI: disable Direct Access Grant by default when creating a new client"; upgrading guide confirms "Direct access grants disabled by default for clients." | ✅ Accurate; this is the load-bearing fail-fast trigger for AD-12. |
| **Keycloak 26.7 still ships ROPC** (memlog / Accepted-Risk Register) | 26.7.0 (2026-07-09) exists; DAG is disabled-by-default but not removed (still re-enableable per client). | ✅ Accurate. |
| **ScopedValue JEP 506 FINAL in JDK 25; StructuredTaskScope JEP 505 PREVIEW** | JEP 506 (Scoped Values) **finalized in JDK 25** (minor change: `orElse` rejects `null`). JEP 505 (Structured Concurrency) **fifth preview** in JDK 25, requires `--enable-preview`. | ✅ Accurate — directly justifies AD-5's "stable primitives only; STS opt-in behind a seam." |
| **Virtual threads JEP 444** | Final/stable since JDK 21; standard on JDK 25. | ✅ Accurate. |
| **Runtime image jlink ~45–66 MB** | Within the commonly-cited jlink slim-image range for JDK 25; not a version claim. | ✅ Plausible; non-version, not web-load-bearing. |

---

## 2. Findings

### FINDING W-1 — "Netty 5 abandoned" rationale is factually wrong (inherited via memlog) · **medium**

**Where:** `.memlog.md:31` ("Netty 5 is DEAD/abandoned (last 5.0.0.Alpha5 Sep-2022) -- do not consider") and `.memlog.md:46` ("Netty 5 abandoned (never consider)"). This rationale underpins the spine's Stack line (`Netty | 4.2.16.Final`).

**What the web shows (2026-07):**
- Netty 5 was paused in **2017** after early alphas, then **revived in 2022** with `5.0.0.Alpha2` (May), `Alpha3`, `Alpha4` (Jul 2022), and `Alpha5` following — not "dead."
- The `main` branch **is** Netty 5 and is in **active development**; a proposal to base Netty 5 on Java 22+ FFM APIs is open (issue #14033); migration guide exists (`netty.io/wiki/netty-5-migration-guide.html`).
- However, **no stable/GA 5.x release exists** — only alphas, no final release date.

**Why it matters:** The version CHOICE (4.2.16.Final) is correct and unaffected — 4.2.x is genuinely the only production-ready line and the right pick for this project. But "abandoned/dead/never consider" is a misstatement of project status. In a security-portfolio piece this is exactly the kind of assertion a reviewer or contributor will challenge, and the spine/memlog should not rest a decision on a false premise when the true premise is stronger and simpler.

**Suggested fix:** replace the rationale with the accurate one — e.g. *"Netty 5 has no stable/GA release (alpha-only; main-branch development ongoing); 4.2.x is the production line for new projects."* Same conclusion, defensible premise.

Sources: <https://netty.io/news/2022/07/22/5-0-0-Alpha4.html> · <https://github.com/netty/netty/issues/13694> · <https://github.com/netty/netty/issues/14033> · <https://netty.io/wiki/netty-5-migration-guide.html>

---

### FINDING W-2 — GraalVM CE patch pin (25.0.2) may lag July 2026 · **low**

**Where:** Stack line "GraalVM ... (Oracle 25.1.3 / CE 25.0.2)"; memlog:33.

**What the web shows:** GraalVM CE 25.0.2 (2026-01-20 CPU) is confirmed real. Secondary sources indicated CE 25.0.3 was slated for 2026-04-21, so by 2026-07 the CE patch floor may have advanced; Oracle GraalVM (not CE) is confirmed at 25.1.3 / 25.0.3. The graalvm.org CE release-notes page still headlines 25.0.2.

**Why it matters little:** AD-23 explicitly makes native-image a **stretch only, no v1 build** — patch-version precision here is non-load-bearing. Flagged only so the pin reads as a floor, not a freeze.

**Suggested fix:** phrase as a floor — *"GraalVM for JDK 25 (Oracle ≥ 25.1.3 / CE ≥ 25.0.2)"* — or drop the CE patch number entirely since no v1 build is produced.

Sources: <https://www.graalvm.org/release-notes/JDK_25/> · <https://www.oracle.com/downloads/graalvm-downloads.html> · <https://eosl.date/eol/product/oracle-graalvm/>

---

### FINDING W-3 — "4.2 IoHandler API" is the transport SPI, not the app-handler replacement · **low (precision)**

**Where:** Stack line "Netty 4.2.16.Final (... 4.2 IoHandler API ...)"; memlog:31,46.

**What the web shows:** In Netty 4.2, `IoHandler` is the **transport-level SPI** (pluggable NIO / Epoll / io_uring — `NioIoHandler`, `EpollIoHandler`, `IoUringIoHandler`), consumed via `MultiThreadIoEventLoopGroup(NioIoHandler.newFactory(...))`. It is **not** a replacement for the application-level `ChannelHandler` / `ChannelPipeline`, which remain the pipeline API in 4.2 (and which the spine itself correctly relies on: `SslHandler → SmppFrameDecoder → SmppCodec → BindInterceptor → RelayHandler` are all `ChannelHandler`s, AD-2).

**Why it matters little:** The spine's *usage* is correct; only the Stack-table phrasing could be read to imply IoHandler supersedes ChannelHandler. Not load-bearing.

**Suggested fix (optional):** *"4.2 IoHandler transport SPI (NIO/Epoll), `ChannelHandler` pipeline retained"* — removes any ambiguity for a reader skimming the stack.

Sources: <https://netty.io/4.2/api/io/netty/channel/IoHandlerContext.html> · <https://netty.io/wiki/netty-4.2-migration-guide.html> · <https://netty.io/news/2025/04/03/4-2-0.html>

---

## 3. Things explicitly checked and found NOT to be problems

- **"jSMPP not 2.3.11"** — the GitHub repo surface does misleadingly show an older line as "Latest"; 3.0.2 is the real current line on Maven Central. The spine's steer-away is correct.
- **CVE-2025-53864 fix threshold (≥10.0.2)** — NVD confirms the vulnerable ranges are exactly 10.0.x<10.0.2 and 9.37.x<9.37.4; 10.9.1 is well clear.
- **Spring Framework 7.0.8 floor** — this is the documented Boot 4.1 requirement, not an arbitrary pick.
- **Keycloak 26.2 DAG-default change** — confirmed by release notes + upgrading guide; it is the correct fail-fast trigger cited in AD-12.
- **"Generational ZGC is the ONLY mode in JDK 25"** — confirmed by JEP 474 + JDK 24 removal of non-gen mode; AD-5's reliance on stable JDK 25 GC primitives is sound.

---

## 4. Sources (primary, cited inline above)

- Oracle Java 25 — <https://www.oracle.com/news/announcement/oracle-releases-java-25-2025-09-16/> · <https://www.oracle.com/java/technologies/java-se-support-roadmap.html>
- OpenJDK JEPs — JEP 444 (virtual threads), JEP 439 (gen-ZGC), JEP 474 (gen-ZGC default), JEP 506 (Scoped Values final), JEP 505 (Structured Concurrency preview) — <https://openjdk.org/jeps/0>
- Oracle Java SE 25 ZGC tuning — <https://docs.oracle.com/en/java/javase/25/gctuning/z-garbage-collector.html>
- Netty — <https://netty.io/news/2025/04/03/4-2-0.html> · <https://netty.io/4.2/api/deprecated-list.html> · <https://netty.io/wiki/netty-4.2-migration-guide.html> · <https://github.com/netty/netty/issues/4893> · <https://github.com/netty/netty/issues/13694> · <https://github.com/netty/netty/issues/14033> · <https://netty.io/news/2022/07/22/5-0-0-Alpha4.html>
- Netty CVE — <https://deps.dev/advisory/osv/GHSA-6mjq-h674-j845>
- Spring — <https://docs.spring.io/spring-boot/system-requirements.html> · <https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.1-Release-Notes> · <https://endoflife.date/spring-boot>
- Nimbus — <https://central.sonatype.com/artifact/com.nimbusds/nimbus-jose-jwt> · <https://nvd.nist.gov/vuln/detail/CVE-2025-53864> · <https://deps.dev/maven/com.nimbusds:nimbus-jose-jwt>
- jSMPP — <https://central.sonatype.com/artifact/org.jsmpp/jsmpp/3.0.2> · <https://github.com/opentelecoms-org/jsmpp>
- GraalVM — <https://www.graalvm.org/release-notes/JDK_25/> · <https://www.graalvm.org/release-calendar/> · <https://www.oracle.com/downloads/graalvm-downloads.html>
- Keycloak — <https://www.keycloak.org/2025/04/keycloak-2620-released> · <https://www.keycloak.org/2026/07/keycloak-2670-released> · <https://www.keycloak.org/docs/latest/upgrading/index.html> · <https://github.com/keycloak/keycloak/issues/30226>
