# Story 5.2 T2 — the distroless Docker deploy shape of the ONE boot jar (FR-DEPLOY-1: this image
# packages 5.1's proxy.jar byte-for-byte over 5.2 T1's jlink runtime; no second build, no forked
# packaging).
#
# LOCATION (spec: "pick one, document"): the image definition is VERSION-CONTROLLED SOURCE here,
# under proxy/src/docker/, while the BUILD CONTEXT is assembled by :proxy:assembleDockerContext
# into proxy/build/docker-image/ — both COPY sources are build outputs, and a Dockerfile may only
# COPY from its own context. That assembly is also fail-closed by construction: any context other
# than the assembled one (e.g. a naive `docker build proxy/src/docker` or `docker build proxy/`)
# fails at the first COPY below — no jlink-image/ or proxy.jar there — and can never produce a
# half-image. Build it with:  ./gradlew :proxy:dockerImage   (tag smpp-proxy:local).
#
# BASE: gcr.io/distroless/base-debian12:nonroot — glibc (matches the temurin-toolchain jlink
# output), ships NO JVM of its own (ours rides on top), and carries the fixed non-root user/group
# 65532 (`nonroot`). No shell, no coreutils, no package manager (spec Design Notes): file modes
# and ownership ride the copy (normalized, see the runtime COPY below) or the runtime mount;
# in-container probes run via `docker exec` of this image's own java.
FROM gcr.io/distroless/base-debian12:nonroot

# 5.2 T1's modular runtime (jdeps-derived module set + the DEPLOY-001 crypto floor
# jdk.crypto.ec / jdk.crypto.cryptoki / java.management). Distroless has no chmod (spec Design
# Notes: modes ride the copy), so :proxy:assembleDockerContext NORMALIZES the copied modes —
# bin/ launchers 0755, everything else 0644, dirs 0755: world-readable for the non-root UID,
# executable exactly
# where the runtime needs it, deterministic across builder umasks. Copied FIRST: the runtime
# changes only when the module set or toolchain changes, so its
# layer stays cached across code-only jar rebuilds. /opt/jre is the ENTRYPOINT's <jre>.
COPY jlink-image/ /opt/jre/

# The ONE artifact — the same bytes the 5.1 JAR shape runs (`java -jar`); never rebuilt here.
COPY proxy.jar /opt/proxy.jar

# DEP-1 (FR-DEPLOY-4, SEC-098 build half): NO secret material rides any layer of this image —
# the two COPYs above are the whole payload. Secrets are runtime MOUNTS under /run/secrets read
# by this UID (T4 proves the contract end-to-end; `docker inspect` Env of a correct run carries
# paths only, never values). The `nonroot` base tag already defaults to this user; the line pins
# it explicitly so the image's own text is the contract, not the base's default.
USER nonroot:nonroot

# The ONE operator flag set — the THIRD kept-in-step representation beside
# docs/operator-jvm-flag-contract.md and PackagedBootSmokeTest.OPERATOR_JVM_FLAGS (nothing parses
# the page; page <-> constant <-> ENTRYPOINT coherence is the review duty of every flag-change
# story). EXEC-FORM IS LOAD-BEARING (DEPLOY-006): java is PID 1, so `docker stop`'s SIGTERM
# reaches the JVM and the AD-22 drain runs before exit 143 — a shell-form entrypoint (/bin/sh as
# PID 1, never forwarding the signal) is exactly the failure that row pins. T3's parity row
# asserts docker inspect's ENTRYPOINT against the Java constant, verbatim.
ENTRYPOINT ["/opt/jre/bin/java", \
            "--enable-preview", \
            "-XX:+UseZGC", \
            "-XX:MaxDirectMemorySize=6442450944", \
            "-Djava.net.preferIPv4Stack=true", \
            "-jar", "/opt/proxy.jar"]

# Cell-args pass-through: CMD defaults to EMPTY, so `docker run <image> <args...>` appends the
# args AFTER the ENTRYPOINT as ordinary Spring run args — exactly the `java ... -jar proxy.jar
# <args>` surface of the JAR shape (args/env override application.yml; cell config rides them,
# 5.1's packaged-smoke precedent). No cell is baked into the image and no secret ever rides a
# default; with no args the app boots the yml defaults and refuses at the AD-17 zero-branch
# matrix rather than half-starting.
CMD []
