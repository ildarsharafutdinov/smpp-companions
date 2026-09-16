package smpp.companion.proxy.bootstrap;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.github.dockerjava.api.command.InspectImageResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Testcontainers;

import smpp.companion.proxy.relay.MockSmsc;
import smpp.companion.proxy.testsupport.DockerRig;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Story 5.2 T3 &mdash; the Docker boot+smoke+parity suite: the SAME one boot jar (5.1's artifact,
 * never rebuilt &mdash; FR-DEPLOY-1) booted as the T2 distroless IMAGE and proven equivalent to
 * the JAR shape end to end. Mirrors {@link PackagedBootSmokeTest} (the JAR-shape spine) row for
 * row, with the container's own mechanics in place of the subprocess rig's. The container rig
 * itself lives in {@link DockerRig} ({@code testsupport/}, Story 6.2 T1 — the BH7 fold; this
 * suite and {@code DockerSecretsE2eTest} are the folded consumers).
 *
 * <p><b>The image is a TEST INPUT, built by the suite.</b> {@link DockerRig#suiteImage}
 * docker-builds from the SAME assembled context {@code :proxy:dockerImage} uses ({@code
 * build/docker-image/} = Dockerfile + jlink runtime + proxy.jar, modes normalized &mdash; one
 * image definition, no drift), and {@code proxy/build.gradle.kts} declares the Dockerfile, the
 * jlink runtime, and the jar as {@code :proxy:test} INPUTS so a change to any of them re-runs
 * this suite against the rebuilt image (the 5.1 stale-jar pattern extended to everything the
 * image bakes; spec Design Notes). Gated by {@code disabledWithoutDocker} &mdash; the repo idiom
 * ({@code RopcSliceLiveTest}) &mdash; so daemon-less builds stay GREEN.
 *
 * <p><b>Host-side satellites over the Testcontainers host-access portal.</b> The containerized
 * reverse-B cell dials the loopback {@link MockSmsc} and the IMMEDIATE-allow token stand-in
 * through {@code host.testcontainers.internal}: {@code Testcontainers.exposeHostPorts} forwards
 * that name (the portal container's address, added by {@code withAccessToHost}) to the test
 * host's loopback, so both satellites stay bound exactly as the JAR-shape rig leaves them. The
 * TLS hop re-points rather than weakens (the stand-in serves the fixture CA's {@code docker-host}
 * cert &mdash; SAN {@code host.testcontainers.internal} &mdash; so the cell's mounted {@code
 * truststore.p12} anchor verifies the chain with FULL hostname checking; spec Design Notes:
 * "parameterize or re-point rather than weakening TLS verification"). The name resolves to an
 * IPv4 /etc/hosts entry and the ENTRYPOINT carries {@code -Djava.net.preferIPv4Stack=true}, so
 * the egress leg of the relay round below IS the DEPLOY-012 Docker arm (an Inet4 connect, proven
 * behaviorally &mdash; the round completes).
 *
 * <p><b>In-container probes without a shell.</b> Distroless has no sh/curl, so the metrics scrape
 * and the forced-GC ZGC-identity scrape run via {@code docker exec} of the image's OWN java
 * against {@link DockerContainerProbe} (compiled test code, {@code docker cp}d in at container
 * create &mdash; the spec's Decision). DEPLOY-011's Docker arm: the endpoint binds the literal
 * 127.0.0.1 INSIDE the container (the yml default 9090 &mdash; this row passes NO metrics port),
 * is reachable ONLY by that in-container exec, and the image declares no exposed port at all
 * (nothing exists to publish).
 *
 * <p><b>The AD-30 interlock, asserted not assumed</b> (same stance as the JAR row): the container
 * carries NO {@code companion.memory.*} args, so the app boots on the shipped yml trio against
 * the ENTRYPOINT's {@code -XX:MaxDirectMemorySize} &mdash; the {@code startup_summary} line pins
 * {@code memory_budget_bytes == direct_memory_ceiling_bytes == } the contract constant, and
 * reaching ready at all is the {@code budget-check: fail} pass under the ENTRYPOINT's flag set.
 * The preview-API arm (DEPLOY-003's Docker half) rides the successful boot itself: the app IS
 * preview-compiled, so a {@code startup_summary} under this ENTRYPOINT is the flag working.
 *
 * <p><b>SIGTERM = {@code docker stop}</b> (DEPLOY-005/006, OBS-015 process-exit). The exec-form
 * ENTRYPOINT makes java PID 1, so the stop's TERM reaches the JVM and the AD-22 walk runs before
 * the container's exit &mdash; <b>143</b> (128+15), the same hook-completed convention the JAR row
 * pins; the drain evidence is the walk's step-3 WARN on stdout, ordered after the couple line.
 *
 * <p>Class-level {@link Timeout} on a separate thread (the house rule): a stuck container must
 * FAIL the row, never hang the suite; {@link DockerRig#close()} is exception-safe and idempotent.
 */
@Tag("integration")
@Tag("deploy")
@Tag("p1")
@Timeout(value = 300, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@Testcontainers(disabledWithoutDocker = true)
@DisplayName("Story 5.2 T3 — Docker boot+smoke+parity: the distroless image boots the one jar, "
        + "relays one round, drains on docker stop")
class DockerImageBootSmokeTest {

    /**
     * The image this suite builds and boots &mdash; the SAME three-entry context {@code
     * :proxy:dockerImage} assembles, under this suite's OWN reaper tag (the per-suite image
     * lifecycle the folded rig keeps; {@link DockerSecretsE2eTest} carries {@code t4-suite}).
     */
    private static final ImageFromDockerfile IMAGE = DockerRig.suiteImage("smpp-proxy:t3-suite");

    /** The image's ENTRYPOINT java path (the Dockerfile's {@code <jre>}/bin/java). */
    private static final String ENTRYPOINT_JAVA = "/opt/jre/bin/java";

    /** The image's jar path (the Dockerfile's COPY destination). */
    private static final String ENTRYPOINT_JAR = "/opt/proxy.jar";

    /** The yml-default metrics port this row never overrides (DEPLOY-011: no host key exists). */
    private static final int METRICS_PORT = 9090;

    // ── the pinned stdout markers (identical literals to the JAR-shape smoke) ───────────────────

    private static final String STARTUP_SUMMARY_MARKER = DockerRig.STARTUP_SUMMARY_MARKER;
    private static final String BIND_ACCEPT_MARKER = "\"event\":\"bind_accept\"";
    private static final String MODE_B_BANNER_MARKER = "MODE B (plaintext) is ACTIVE on a REVERSE instance";
    private static final String DRAIN_FORCE_CLOSE_MARKER =
            "force-closed 1 live pair(s) as SHUTDOWN_DRAIN";

    /** SMPP 3.4 &sect;4.1.2 opaque PDUs the relay carries unparsed (AD-3). */
    private static final int SUBMIT_SM = 0x00000004;
    private static final int DELIVER_SM = 0x00000005;

    /** Per-invocation temp dir (the mounted secret material). */
    @TempDir
    Path dir;

    @Test
    @DisplayName("docker boot+smoke: the ENTRYPOINT's flag set boots the reverse-B cell (secrets "
            + "mounted) → startup_summary at the yml-default AD-30 budget (== the constant's "
            + "ceiling), one bind→relay round via the published port against the host MockSmsc, "
            + "the in-container-only /metrics scrape with binder gauges, and docker stop walks the "
            + "AD-22 drain WARN in order before exit 143")
    void dockerBootRelaysOneRoundAndDrainsOnDockerStop() throws Exception {
        try (DockerRig rig = DockerRig.launchReverseBCell(IMAGE, dir, "docker-smoke-idp")) {
            rig.awaitStartupSummary();

            // (1) The boot summary: the resolved cell AND the AD-30 interlock, pinned on the line —
            // identical shape to the JAR smoke (FR-DEPLOY-1: the two shapes run the same bytes).
            String summary = lineContaining(rig.stdout(), STARTUP_SUMMARY_MARKER);
            assertThat(summary)
                    .as("startup_summary names the reverse-B cell this row launched (listener on the "
                            + "container wildcard — the published port is the ingress)")
                    .contains("\"role\":\"reverse\"", "\"mode\":\"b\"",
                            "\"smpp_bind_host\":\"0.0.0.0\"",
                            "\"smpp_bind_port\":" + rig.bindPort(),
                            "\"metrics_port\":" + METRICS_PORT)
                    .as("the AD-30 interlock under the ENTRYPOINT flags: the yml-default derived "
                            + "budget EQUALS the live ceiling the ENTRYPOINT's "
                            + "-XX:MaxDirectMemorySize set (no companion.memory.* args ride this run)")
                    .contains("\"memory_budget_bytes\":" + PackagedBootSmokeTest.OPERATOR_MAX_DIRECT_MEMORY_BYTES,
                            "\"direct_memory_ceiling_bytes\":"
                                    + PackagedBootSmokeTest.OPERATOR_MAX_DIRECT_MEMORY_BYTES);

            // (2) The Mode B banner rides the container's stdout as a WARN JSON line (the JAR row's
            // swap, re-proven in the IMAGE shape) — and never lands on the container's raw stderr
            // (docker keeps the two streams separately fetchable).
            assertThat(lineContaining(rig.stdout(), MODE_B_BANNER_MARKER))
                    .as("the mode banner rides the container stdout as a WARN JSON line")
                    .contains("\"level\":\"WARN\"");
            assertThat(rig.stderr())
                    .as("the mode banner leaves the container's stderr alone")
                    .doesNotContain(MODE_B_BANNER_MARKER);

            // (3) One bind→relay round on a REAL socket through the PUBLISHED port: bind → ROPC
            // Allow at the host-side stand-in IdP (full TLS hostname verification over the
            // host-access portal — the DEPLOY-012 Inet4 egress leg) → egress dial through
            // host.testcontainers.internal → the mock's ROK → couple; one submit_sm INGRESS-relayed
            // byte-exact; one deliver_sm EGRESS-relayed byte-exact.
            Socket legacy = rig.connectLegacy();
            byte[] bind = RelayTestFixtures.bindRequest(1, "legacy1", "pw123456");
            RelayTestFixtures.writePdu(legacy, bind);
            DockerRig.assertRokBindResp(RelayTestFixtures.readPdu(legacy), 1);
            MockSmsc.Session session = rig.smsc().awaitSession(0);
            assertThat(session.bindFrame())
                    .as("AD-14: the original bind crossed the containerized relay byte-exact")
                    .isEqualTo(bind);
            byte[] submit = opaquePdu(SUBMIT_SM, 201, "DOCKER-SUBMIT");
            RelayTestFixtures.writePdu(legacy, submit);
            assertThat(session.awaitPdus(1))
                    .as("the submit_sm was relayed to the SMSC byte-exact (no drop, no corruption)")
                    .containsExactly(submit);
            byte[] deliver = opaquePdu(DELIVER_SM, 301, "DOCKER-DELIVER");
            session.deliver(deliver);
            assertThat(RelayTestFixtures.readPdu(legacy))
                    .as("the deliver_sm was relayed back byte-exact")
                    .isEqualTo(deliver);
            // The pair stays OPEN from here into docker stop — the drain body's live pair (below).

            // (4) The in-container /metrics scrape (DEPLOY-011 Docker arm): the endpoint answers
            // ONLY inside the container, on the literal loopback, via the image's own java running
            // the cp'd probe — the standard JVM binder gauges beside the custom ones, and the
            // round itself visible (one PDU per leg).
            String scrape = inContainerScrape(rig);
            assertThat(scrape)
                    .as("the container's loopback metrics listener serves the whole gauge surface "
                            + "to an in-container exec (and to nothing else)")
                    .startsWith("HTTP/1.1 200")
                    .contains("jvm_memory_used_bytes", "jvm_gc_live_data_size_bytes")
                    .contains("relay_direct_memory_used_bytes", "relay_connections_closed_total")
                    .as("the relay round is visible in the in-container scrape (one PDU per leg)")
                    .contains("relay_pdus_total{direction=\"INGRESS\"} 1.0")
                    .contains("relay_pdus_total{direction=\"EGRESS\"} 1.0");

            // (4b) …and the IMAGE side carries no exposed-ports declaration at all — the bite is
            // image text, not run config (the run's port bindings only mirror this rig's own
            // withExposedPorts, so they could never go RED on an image change): an `EXPOSE 9090`
            // regression in the Dockerfile turns this RED. Structurally, nothing in the image
            // offers a publishable surface — the endpoint binds the 127.0.0.1 literal INSIDE the
            // container and no host key exists to widen it (DEPLOY-011: a `-p 9090` finds
            // nothing listening even if published).
            InspectImageResponse image = DockerClientFactory.instance()
                    .client()
                    .inspectImageCmd(IMAGE.get())
                    .exec();
            assertThat(image.getConfig().getExposedPorts())
                    .as("the image declares NO exposed ports — the metrics endpoint (and every "
                            + "listener) is reachable only in-container")
                    .isNullOrEmpty();

            // (5) docker stop (SIGTERM to PID 1 — the exec-form ENTRYPOINT) → the AD-22 walk:
            // acceptor stop → deny (no-op) → the drain body polls the live pair to the 2s deadline
            // and force-closes it (the OBS-020 WARN) → release → quiesce → exit 143.
            rig.container().getDockerClient()
                    .stopContainerCmd(rig.container().getContainerId())
                    .withTimeout(30)
                    .exec();
            Long exitCode = rig.container().getDockerClient()
                    .inspectContainerCmd(rig.container().getContainerId())
                    .exec()
                    .getState()
                    .getExitCodeLong();
            assertThat(exitCode)
                    .as("clean docker-stop exit: 143 = the JVM convention for a hook-completed "
                            + "SIGTERM shutdown (java is PID 1 via the exec-form ENTRYPOINT; a "
                            + "shell-form wrapper would strand the walk and time the stop out)")
                    .isEqualTo(143);

            String out = rig.stdout();
            int summaryIdx = out.indexOf(STARTUP_SUMMARY_MARKER);
            int acceptIdx = out.indexOf(BIND_ACCEPT_MARKER);
            int drainIdx = out.indexOf(DRAIN_FORCE_CLOSE_MARKER);
            assertThat(summaryIdx).as("the boot summary is on the container stdout").isGreaterThanOrEqualTo(0);
            assertThat(lineContaining(out, BIND_ACCEPT_MARKER))
                    .as("the couple is a JSON INFO line naming the system_id")
                    .contains("\"system_id\":\"legacy1\"");
            assertThat(acceptIdx)
                    .as("ordered stream: the couple line follows the startup summary")
                    .isGreaterThan(summaryIdx);
            assertThat(drainIdx)
                    .as("ordered stream: the AD-22 step-3 drain WARN follows the couple line (the "
                            + "pair was live at the signal and was force-closed at the deadline)")
                    .isGreaterThan(acceptIdx);
            assertThat(lineContaining(out, DRAIN_FORCE_CLOSE_MARKER))
                    .as("the drain line is the walk's WARN (OBS-020), naming the 2s deadline this "
                            + "row configured")
                    .contains("\"level\":\"WARN\"", "shutdown drain deadline (PT2S) expired");
        }
    }

    @Test
    @DisplayName("flag parity (DEPLOY-003/004 Docker halves, DEPLOY-006 exec-form half): the "
            + "image's ENTRYPOINT is the contract set VERBATIM — the exact list "
            + "[java, OPERATOR_JVM_FLAGS..., -jar, /opt/proxy.jar], no env flag-fork")
    void imageEntrypointCarriesTheContractFlagSetVerbatim() throws Exception {
        DockerRig.assertContextAssembled();
        InspectImageResponse image = DockerClientFactory.instance()
                .client()
                .inspectImageCmd(IMAGE.get())
                .exec();
        List<String> expected = new ArrayList<>();
        expected.add(ENTRYPOINT_JAVA);
        expected.addAll(PackagedBootSmokeTest.OPERATOR_JVM_FLAGS);
        expected.add("-jar");
        expected.add(ENTRYPOINT_JAR);
        assertThat(image.getConfig().getEntrypoint())
                .as("docker inspect ENTRYPOINT == [java] + PackagedBootSmokeTest.OPERATOR_JVM_FLAGS "
                        + "+ [-jar, proxy.jar], verbatim — the THIRD kept-in-step representation of "
                        + "the ONE flag set beside the contract page and the Java constant; a non-null "
                        + "JSON-array entrypoint IS the exec form (DEPLOY-006)")
                .containsExactlyElementsOf(expected);
        assertThat(image.getConfig().getUser())
                .as("the image pins its own non-root contract text (USER nonroot:nonroot — the "
                        + "distroless UID 65532; T4 proves the mounted-secrets readability)")
                .isEqualTo("nonroot:nonroot");
        String[] env = image.getConfig().getEnv();
        assertThat(env == null ? List.<String>of()
                : java.util.Arrays.stream(env).map(e -> e.split("=", 2)[0]).toList())
                .as("no launcher-env flag fork: the ENTRYPOINT is the only flag carrier (the "
                        + "JDK_JAVA_OPTIONS/JAVA_TOOL_OPTIONS channels are absent from the image)")
                .doesNotContain("JDK_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "JAVA_OPTS", "_JAVA_OPTIONS");
    }

    @Test
    @DisplayName("ZGC gc-identity arm (DEPLOY-004's deferred introspection): a FORCED GC cycle in "
            + "the PID-1 proxy (jcmd GC.run over the hand-spoken attach protocol, run by the image's "
            + "own java) then the in-container scrape shows the ZGC-named jvm_gc_* timer families — "
            + "deterministic after the forced cycle")
    void forcedGcThenInContainerScrapeNamesZgc() throws Exception {
        try (DockerRig rig = DockerRig.launchReverseBCell(IMAGE, dir, "docker-smoke-idp")) {
            rig.awaitStartupSummary();

            // (1) arm the target's lazy attach listener: the trigger file, then SIGQUIT to PID 1
            // (the thread dump the signal also prints lands harmlessly on stdout).
            assertThat(rig.execProbe("prepare-attach", "1").getExitCode())
                    .as("the attach trigger file was created in the container")
                    .isZero();
            rig.container().getDockerClient()
                    .killContainerCmd(rig.container().getContainerId())
                    .withSignal("QUIT")
                    .exec();

            // (2) force the cycle in the TARGET JVM — the image's own java speaking the JDK attach
            // protocol over the AF_UNIX socket (the jlink runtime carries no jdk.attach module and
            // the app runs no JMX agent; GC.run is the one deterministic forced cycle).
            Container.ExecResult forced = rig.execProbe("force-gc", "1");
            assertThat(forced.getExitCode())
                    .as("the attach jcmd GC.run completed cleanly — stderr: <%s>", forced.getStderr())
                    .isZero();
            assertThat(forced.getStdout())
                    .as("the attach reply carries completion status 0")
                    .contains("attach-reply 0");

            // (3) the scrape after the forced cycle: the lazily-created jvm_gc_* timer families
            // name the ZGC collector (JDK 25 generational ZGC: "ZGC Major/Minor Cycles/Pauses"),
            // with OUR forced cycle's cause — a jcmd GC.run reports as "Diagnostic Command" (not
            // System.gc()'s cause; pinned on the first run) — the runtime GC identity under the
            // ENTRYPOINT's -XX:+UseZGC, deterministic instead of awaited.
            String scrape = inContainerScrape(rig);
            assertThat(scrape)
                    .as("a pause timer exists for a ZGC-named collector on the forced cycle's cause")
                    .contains("jvm_gc_pause_seconds")
                    .contains("cause=\"Diagnostic Command\",gc=\"ZGC");
            assertThat(scrape)
                    .as("ZGC is a concurrent collector — its cycles land in the concurrent family")
                    .contains("jvm_gc_concurrent_phase_time_seconds")
                    .contains("gc=\"ZGC");
            assertThat(scrape)
                    .as("the eager binder gauges ride the same in-container scrape (DEPLOY-011)")
                    .contains("jvm_memory_used_bytes", "jvm_gc_live_data_size_bytes",
                            "relay_direct_memory_used_bytes");
        }
    }

    // ── probes and pinned wire literals ───────────────────────────────────────────────────────

    /** The probe's /metrics scrape inside the container (DEPLOY-011's Docker arm). */
    private String inContainerScrape(DockerRig rig) throws IOException, InterruptedException {
        Container.ExecResult scrape = rig.execProbe("scrape", String.valueOf(METRICS_PORT));
        assertThat(scrape.getExitCode())
                .as("the in-container probe scrape succeeded — stderr: <%s>", scrape.getStderr())
                .isZero();
        return scrape.getStdout();
    }

    /** The first stream line containing {@code marker} (fails naming the whole stream if absent). */
    private static String lineContaining(String stream, String marker) {
        for (String line : stream.lines().toList()) {
            if (line.contains(marker)) {
                return line;
            }
        }
        fail("no line contains <" + marker + "> — stream: <" + stream + ">");
        return null; // unreachable — fail() throws
    }

    /** An OPAQUE non-bind PDU carrying an ASCII tag body (never parsed — AD-3; the tag is the probe). */
    private static byte[] opaquePdu(int commandId, int sequence, String tag) {
        byte[] body = RelayTestFixtures.ascii(tag);
        return RelayTestFixtures.assemble(commandId, 0, sequence, body.length, out -> out.put(body));
    }
}
