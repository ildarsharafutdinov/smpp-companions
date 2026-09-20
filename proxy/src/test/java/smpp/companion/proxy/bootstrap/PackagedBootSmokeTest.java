package smpp.companion.proxy.bootstrap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import com.sun.net.httpserver.HttpsServer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import smpp.companion.proxy.relay.MockSmsc;
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.testsupport.TokenIdpStandIn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Story 5.1 T5 &mdash; the packaged boot+smoke: the REAL boot jar launched as a bare
 * {@code java -jar} SUBPROCESS (the production main, application.yml defaults overridable by args
 * &mdash; never an ApplicationContextRunner stand-in for the shape being proven) with the operator
 * JVM-flag contract's set, one real-socket bind&rarr;relay round through the loopback
 * {@link MockSmsc}, and SIGTERM &rarr; the AD-22 drain WARN, in order, before a clean exit. This is
 * the JAR half of DEPLOY-003/004 (the flag set live at runtime in the packaged shape) plus the
 * catalog matrix rows "packaged boot" and "SIGTERM on packaged shape".
 *
 * <p><b>The launch constant (the executable flag-set definition).</b> {@link #OPERATOR_JVM_FLAGS}
 * mirrors {@code docs/operator-jvm-flag-contract.md} (Story 5.1 T2). By owner rule (2026-09-10)
 * NOTHING in the repository parses that page &mdash; the page and this constant are the two
 * kept-in-step representations of the ONE flag set (FR-DEPLOY-1), so a flag change is a story
 * touching BOTH and the reviewer checks they match. The later Docker entrypoint must carry the
 * identical set; neither deploy shape authors its own flags.
 *
 * <p><b>The AD-30 interlock, asserted not assumed</b> (Design Note: "pick the value once, assert
 * it in the smoke &mdash; do not fork yml"): the smoke passes NO {@code companion.memory.*} keys,
 * so the child boots on the shipped application.yml trio (64 &times; 1024 &times; 1.5 &rarr; a
 * 6,442,450,944-byte derived budget) against the constant's {@code -XX:MaxDirectMemorySize}. The
 * row then pins equality on the {@code startup_summary} line &mdash; {@code memory_budget_bytes}
 * equals {@code direct_memory_ceiling_bytes} equals {@link #OPERATOR_MAX_DIRECT_MEMORY_BYTES}
 * &mdash; and reaching {@code startup_summary} at all IS the AD-30 pass under the constant's flags
 * ({@code budget-check: fail} would have refused the boot otherwise). Retuning either side (yml
 * trio or constant) without the other turns this row RED at the next run, exactly the operator
 * contract the page states.
 *
 * <p><b>Flag introspection, subprocess form.</b> The catalog's DEPLOY-003/004 technique reads
 * {@code RuntimeMXBean.getInputArguments()} &mdash; impossible from outside the child &mdash; so
 * the row reads the live process's {@code /proc/<pid>/cmdline} (the packaged smoke is a
 * Linux/SIGTERM suite by construction) and asserts all four flags verbatim: this is the
 * "flags are on the launch" half; the MaxDirectMemorySize half is additionally proven by the
 * ceiling field above, and the preview half has its own refusal row.
 *
 * <p><b>The preview arm, automated</b> (matrix row 2; the T1 manual proof's CI row): the identical
 * launch minus {@code --enable-preview} must refuse HARD. Only the classes that actually use a
 * preview API carry the preview class-file marking (the {@code RopcBindCredentialVerifier} family
 * &mdash; JEP 505 StructuredTaskScope, AD-5), so the refusal surfaces when the verifier bean is
 * first instantiated during the context refresh: {@code UnsupportedClassVersionError} naming
 * {@code --enable-preview}, exit 1, no {@code startup_summary}. Fail-closed by construction &mdash;
 * the contract flag is the single load-bearing preview mechanism (the manifest attribute was
 * proven inert and dropped, owner amendment 2026-09-10).
 *
 * <p><b>SIGTERM = {@code Process.destroy()}}</b> (TERM on Linux). The asserted exit status is
 * <b>143</b> &mdash; the JVM's convention for a SIGTERM-initiated shutdown whose hooks ran to
 * completion (128+15): it discriminates the clean walk (143) from a boot crash (1) and from this
 * rig's own forcible kill (137). The drain evidence is the walk's step-3 WARN
 * ("force-closed N live pair(s) as SHUTDOWN_DRAIN", OBS-020): the smoke holds the coupled pair
 * OPEN across the signal (neither peer half-closes), so the drain body provably polls the registry
 * to the row's SHORT drain deadline and force-closes there &mdash; the line's presence, its WARN
 * level, and its position AFTER the couple line and BEFORE the exit are all asserted.
 *
 * <p><b>Why the cell args are stated here, not via {@code TestCompanionConfigs}:</b> the runner-cell
 * factory bakes the minimal 1/1/1.0 memory trio (a capped TEST-JVM ceiling needs it) and the shared
 * discovery stand-in's provider-url &mdash; both wrong for this boot (the interlock needs the yml
 * defaults; the couple needs the IMMEDIATE-allow token stand-in). The packaged row states its arg
 * list explicitly over the same fixture MATERIAL ({@link RelayTestFixtures} trust store + secret
 * file), so the packaged cell has one honest source too.
 *
 * <p>Class-level {@link Timeout} on a separate thread: a stuck child must FAIL this row, never hang
 * the suite (the BindInterceptorTest pattern); {@link Rig#close()} is exception-safe and idempotent
 * (the house rule &mdash; a failed row must not strand the child JVM, the mock, or the stand-in).
 */
@Tag("integration")
@Tag("deploy")
@Tag("p1")
@Timeout(value = 120, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@DisplayName("Story 5.1 T5 — packaged boot+smoke: java -jar the real boot jar, one relay round, "
        + "SIGTERM drain")
class PackagedBootSmokeTest {

    /**
     * The built boot jar (Story 5.1 T1: pinned main class + the stable archive name {@code
     * proxy.jar}). Resolved relative to the proxy module dir (the {@code :proxy:test} CWD — the
     * {@code MetricsEndpointTest} source-scan idiom); {@code proxy/build.gradle.kts} wires the
     * {@code bootJar} task both as a test DEPENDENCY (the jar exists before tests run) and as a
     * test INPUT (the smoke re-runs when the jar changes — never a stale-jar incremental run).
     */
    private static final Path BOOT_JAR = Path.of("build", "libs", "proxy.jar");

    /**
     * The contract's {@code -XX:MaxDirectMemorySize} value, as ONE number (6,442,450,944 = 6 GiB =
     * the codec max frame 65,536 &times; the shipped yml trio 64 &times; 1024 &times; 1.5 &mdash;
     * the AD-30 derivation; see the contract page's per-flag rationale). The flag string and both
     * {@code startup_summary} assertions below derive from this constant, so the page, the launch,
     * and the interlock pin cannot drift apart inside the row.
     */
    static final long OPERATOR_MAX_DIRECT_MEMORY_BYTES = 6_442_450_944L;

    /**
     * The ONE operator JVM-flag set for the runnable-JAR launch shape &mdash; the EXECUTABLE
     * definition of {@code docs/operator-jvm-flag-contract.md} (Story 5.1 T2; FR-DEPLOY-1; the
     * DEPLOY-003/004 JAR halves). By owner rule (2026-09-10) nothing parses that page: the page and
     * this constant are the two kept-in-step representations, a flag change is a story touching
     * BOTH (page &harr; constant coherence is the reviewer's check), and the later Docker
     * entrypoint must carry the identical set.
     */
    static final List<String> OPERATOR_JVM_FLAGS = List.of(
            "--enable-preview",
            "-XX:+UseZGC",
            "-XX:MaxDirectMemorySize=" + OPERATOR_MAX_DIRECT_MEMORY_BYTES,
            "-Djava.net.preferIPv4Stack=true");

    // ── the pinned stdout markers (literals, independent of the production log sites) ──────────

    private static final String STARTUP_SUMMARY_MARKER = "\"event\":\"startup_summary\"";
    private static final String BIND_ACCEPT_MARKER = "\"event\":\"bind_accept\"";
    private static final String MODE_B_BANNER_MARKER = "MODE B (plaintext) is ACTIVE on a REVERSE instance";
    private static final String DRAIN_FORCE_CLOSE_MARKER =
            "force-closed 1 live pair(s) as SHUTDOWN_DRAIN";

    /** The bind_resp wire contract, pinned as LITERALS (the RelayA1SmokeTest discipline). */
    private static final int BIND_TRANSCEIVER_RESP = 0x80000009;

    /** SMPP 3.4 &sect;4.1.2 opaque PDUs the relay carries unparsed (AD-3). */
    private static final int SUBMIT_SM = 0x00000004;
    private static final int DELIVER_SM = 0x00000005;

    /** The bound poll deadline for the packaged boot (a loaded CI runner boots the fat jar slowly). */
    private static final long BOOT_DEADLINE_MILLIS = 45_000;

    /** The SIGTERM drain window: 2s drain deadline + release/quiesce, bounded generously. */
    private static final long EXIT_DEADLINE_MILLIS = 30_000;

    /** Per-invocation temp dir (the oidc secret + IdP trust-store fixtures and the captured streams). */
    @TempDir
    Path dir;

    @Test
    @DisplayName("packaged boot+smoke: the contract flag set `java -jar`s the real jar → "
            + "startup_summary at the yml-default AD-30 budget (== the constant's ceiling), "
            + "one real-socket bind→relay round through the loopback MockSmsc, and SIGTERM walks "
            + "the AD-22 drain WARN in order before a clean exit")
    void packagedBootRelaysOneRoundAndDrainsOnSigterm() throws Exception {
        try (Rig rig = launch(OPERATOR_JVM_FLAGS)) {
            awaitStartupSummary(rig);

            // (1) The boot summary: the resolved cell AND the AD-30 interlock, pinned on the line.
            String summary = lineContaining(output(rig.stdout), STARTUP_SUMMARY_MARKER);
            assertThat(summary)
                    .as("startup_summary names the reverse-B cell this row launched")
                    .contains("\"role\":\"reverse\"", "\"mode\":\"b\"",
                            "\"smpp_bind_host\":\"127.0.0.1\"",
                            "\"smpp_bind_port\":" + rig.bindPort,
                            "\"metrics_port\":" + rig.metricsPort)
                    .as("the AD-30 interlock: the yml-default derived budget EQUALS the live "
                            + "ceiling the constant's -XX:MaxDirectMemorySize set (reaching ready "
                            + "at all is the budget-check:fail pass; equality is the no-fork pin)")
                    .contains("\"memory_budget_bytes\":" + OPERATOR_MAX_DIRECT_MEMORY_BYTES,
                            "\"direct_memory_ceiling_bytes\":" + OPERATOR_MAX_DIRECT_MEMORY_BYTES);

            // (2) The Mode B banner is on the JSON stream at JAR boot (T3's swap, visible in the
            // packaged shape) — ONE WARN line, never a stderr println.
            assertThat(lineContaining(output(rig.stdout), MODE_B_BANNER_MARKER))
                    .as("the mode banner rides the packaged stdout as a WARN JSON line")
                    .contains("\"level\":\"WARN\"");
            // (2b) …and the banner's stderr half (T3's AC, proven here in the DEPLOYED shape): the
            // banner text never lands on the child's raw stderr. Absence-of-marker, not isBlank() —
            // a JVM launched with JDK_JAVA_OPTIONS legitimately prints "Picked up ..." there.
            assertThat(output(rig.stderr))
                    .as("the mode banner leaves the packaged stderr alone (T3's second half)")
                    .doesNotContain(MODE_B_BANNER_MARKER);

            // (3) DEPLOY-003/004's JAR halves: the whole contract set, verbatim, on the LIVE
            // launch (RuntimeMXBean.getInputArguments, adapted to the subprocess via /proc).
            Path cmdline = Path.of("/proc", String.valueOf(rig.process.pid()), "cmdline");
            assertThat(cmdline)
                    .as("/proc exposes the child's command line (Linux — this suite's platform: "
                            + "the SIGTERM drain row is Linux by construction)")
                    .isRegularFile();
            assertThat(output(cmdline).replace('\0', ' '))
                    .as("the operator flag set is present, verbatim, on the packaged launch")
                    .contains("--enable-preview", "-XX:+UseZGC",
                            "-XX:MaxDirectMemorySize=" + OPERATOR_MAX_DIRECT_MEMORY_BYTES,
                            "-Djava.net.preferIPv4Stack=true");

            // (4) One bind→relay round on a REAL socket (the RelayA1SmokeTest idiom; the proxy is
            // the subprocess, the client and the mock live in this JVM on the loopback): bind →
            // ROPC Allow at the stand-in IdP → egress dial → the mock's ROK → couple; one submit_sm
            // INGRESS-relayed byte-exact; one deliver_sm EGRESS-relayed byte-exact.
            Socket legacy = rig.connectLegacy();
            byte[] bind = RelayTestFixtures.bindRequest(1, "legacy1", "pw123456");
            RelayTestFixtures.writePdu(legacy, bind);
            assertRokBindResp(RelayTestFixtures.readPdu(legacy), 1);
            MockSmsc.Session session = rig.smsc.awaitSession(0);
            assertThat(session.bindFrame())
                    .as("AD-14: the original bind crossed the packaged relay byte-exact")
                    .isEqualTo(bind);
            byte[] submit = opaquePdu(SUBMIT_SM, 201, "PACKAGED-SUBMIT");
            RelayTestFixtures.writePdu(legacy, submit);
            assertThat(session.awaitPdus(1))
                    .as("the submit_sm was relayed to the SMSC byte-exact (no drop, no corruption)")
                    .containsExactly(submit);
            byte[] deliver = opaquePdu(DELIVER_SM, 301, "PACKAGED-DELIVER");
            session.deliver(deliver);
            assertThat(RelayTestFixtures.readPdu(legacy))
                    .as("the deliver_sm was relayed back byte-exact")
                    .isEqualTo(deliver);
            // The pair stays OPEN from here into SIGTERM — the drain body's live pair (below).

            // (5) The packaged /metrics scrape: the standard JVM binder gauges beside the custom
            // gauges (T4's surface, proven in the PACKAGED shape), and the round itself visible.
            assertThat(scrape(rig.metricsPort))
                    .as("the packaged metrics listener is bound and serves the whole gauge surface")
                    .startsWith("HTTP/1.1 200")
                    .contains("jvm_memory_used_bytes", "jvm_gc_live_data_size_bytes")
                    .contains("relay_direct_memory_used_bytes", "relay_connections_closed_total")
                    .as("the relay round is visible in the packaged scrape (one PDU per leg; the "
                            + "label is the Direction enum name — the closed 2-value set, AD-19)")
                    .contains("relay_pdus_total{direction=\"INGRESS\"} 1.0")
                    .contains("relay_pdus_total{direction=\"EGRESS\"} 1.0")
                    .as("Story 8.1 T2: each relayed PDU also recorded its transit — one record per "
                            + "leg, the same single fire as the counter (timer _count rows render "
                            + "integer, unlike the 1.0 counters)")
                    .contains("relay_pdus_transit_seconds_count{direction=\"INGRESS\"} 1")
                    .contains("relay_pdus_transit_seconds_count{direction=\"EGRESS\"} 1");

            // (6) SIGTERM → the AD-22 walk: acceptor stop → deny (no-op) → the drain body polls the
            // live pair to the 2s deadline and force-closes it (the OBS-020 WARN) → release →
            // quiesce → exit. Ordered on the stream: startup_summary < bind_accept < the drain WARN.
            rig.process.destroy(); // SIGTERM (Linux)
            assertThat(rig.process.waitFor(EXIT_DEADLINE_MILLIS, TimeUnit.MILLISECONDS))
                    .as("the packaged walk must exit on its own — never a hang")
                    .withFailMessage("the packaged process did not exit after SIGTERM — "
                            + "stdout so far: <%s>", output(rig.stdout))
                    .isTrue();
            assertThat(rig.process.exitValue())
                    .as("clean SIGTERM exit: 143 = the JVM convention for a hook-completed "
                            + "SIGTERM shutdown (a crash is 1, this rig's forcible kill is 137)")
                    .isEqualTo(143);

            String out = output(rig.stdout);
            int summaryIdx = out.indexOf(STARTUP_SUMMARY_MARKER);
            int acceptIdx = out.indexOf(BIND_ACCEPT_MARKER);
            int drainIdx = out.indexOf(DRAIN_FORCE_CLOSE_MARKER);
            assertThat(summaryIdx).as("the boot summary is on the packaged stream").isGreaterThanOrEqualTo(0);
            assertThat(lineContaining(out, BIND_ACCEPT_MARKER))
                    .as("the couple is a JSON INFO line naming the system_id")
                    .contains("\"system_id\":\"legacy1\"");
            assertThat(acceptIdx)
                    .as("ordered stream: the couple line follows the startup summary")
                    .isGreaterThan(summaryIdx);
            assertThat(drainIdx)
                    .as("ordered stream: the AD-22 step-3 drain WARN follows the couple line "
                            + "(the pair was live at the signal and was force-closed at the deadline)")
                    .isGreaterThan(acceptIdx);
            assertThat(lineContaining(out, DRAIN_FORCE_CLOSE_MARKER))
                    .as("the drain line is the walk's WARN (OBS-020), and names the 2s deadline "
                            + "this row configured")
                    .contains("\"level\":\"WARN\"", "shutdown drain deadline (PT2S) expired");
        }
    }

    @Test
    @DisplayName("preview arm (matrix row 2, DEPLOY-003's JAR half automated): the identical "
            + "launch WITHOUT --enable-preview refuses HARD — UnsupportedClassVersionError naming "
            + "--enable-preview, exit 1, no startup_summary")
    void packagedBootWithoutEnablePreviewRefusesHard() throws Exception {
        List<String> withoutPreview = OPERATOR_JVM_FLAGS.stream()
                .filter(flag -> !"--enable-preview".equals(flag))
                .toList();
        try (Rig rig = launch(withoutPreview)) {
            assertThat(rig.process.waitFor(EXIT_DEADLINE_MILLIS, TimeUnit.MILLISECONDS))
                    .as("the preview-less packaged boot must refuse on its own — fail-closed, "
                            + "never a hang (a hung boot would need this rig's forcible kill)")
                    .withFailMessage("the preview-less packaged process did not exit — stdout: <%s>, "
                            + "stderr: <%s>", output(rig.stdout), output(rig.stderr))
                    .isTrue();
            assertThat(rig.process.exitValue())
                    .as("the refusal is a failed boot: SpringApplication exits 1")
                    .isEqualTo(1);
            String combined = output(rig.stdout) + "\n" + output(rig.stderr);
            assertThat(combined)
                    .as("the preview refusal names the flag, verbatim (the load-bearing preview "
                            + "mechanism is the contract flag — the manifest carries no marking)")
                    .contains("UnsupportedClassVersionError",
                            "Preview features are not enabled",
                            "--enable-preview")
                    .as("no startup summary — the refusal fires during the context refresh, "
                            + "before the app is ready")
                    .doesNotContain(STARTUP_SUMMARY_MARKER);
        }
    }

    // ── the rig: the launched jar + its loopback satellites ────────────────────────────────────

    /**
     * Everything one row holds: the subprocess (the packaged jar), its captured streams, and the
     * two loopback satellites the round needs ({@link MockSmsc} — the SMSC the egress leg dials;
     * the IMMEDIATE-allow token stand-in — the IdP the packaged ROPC adapter dials for the verdict).
     * {@link #close()} is idempotent and exception-safe (the house rule): a failed row must not
     * strand the child JVM, the mock's loop, or the stand-in's executor.
     */
    private static final class Rig implements AutoCloseable {

        final MockSmsc smsc;
        final com.sun.net.httpserver.HttpsServer idp;
        final Process process;
        final Path stdout;
        final Path stderr;
        final int bindPort;
        final int metricsPort;

        /** The coupled pair's legacy leg — HELD OPEN into SIGTERM (the drain body's live pair). */
        Socket legacy;

        Rig(MockSmsc smsc, HttpsServer idp, Process process,
                Path stdout, Path stderr, int bindPort, int metricsPort) {
            this.smsc = smsc;
            this.idp = idp;
            this.process = process;
            this.stdout = stdout;
            this.stderr = stderr;
            this.bindPort = bindPort;
            this.metricsPort = metricsPort;
        }

        /** A legacy loopback client on the packaged acceptor (the RelayA1SmokeTest idiom). */
        Socket connectLegacy() throws IOException {
            Socket socket = new Socket(InetAddress.getLoopbackAddress(), bindPort);
            socket.setSoTimeout(10_000);
            legacy = socket;
            return socket;
        }

        @Override
        public void close() {
            if (legacy != null) {
                try {
                    legacy.close();
                } catch (IOException ignored) {
                    // teardown best-effort — the walk's own close is what the row asserts
                }
            }
            process.destroyForcibly(); // no-op on an already-exited child (the normal path)
            try {
                smsc.close();
            } catch (Exception ignored) {
                // already closed
            }
            try {
                idp.stop(0);
            } catch (Exception ignored) {
                // already stopped
            }
        }
    }

    /**
     * Launches the packaged jar as a subprocess: {@code java <flags> -jar proxy.jar <cell args>},
     * both streams redirected to files under {@code dir} (redirect-files, not pipes — a child can
     * never block on an undrained pipe buffer, and the poller reads a growing file). The same
     * complete reverse-B cell serves both rows, so the preview arm fails for ONE reason only (the
     * dropped flag) — config binding passes and the refusal lands at the verifier class load.
     */
    private Rig launch(List<String> jvmFlags) throws IOException {
        assertThat(BOOT_JAR)
                .as("the boot jar must exist (:proxy:test dependsOn bootJar; the jar is a test "
                        + "input — an incremental run rebuilds it before this row)")
                .isRegularFile();
        String javaBin = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        MockSmsc smsc = MockSmsc.start();
        HttpsServer idp = null;
        Process process = null;
        try {
            // park=false: the token handler answers a VALID 200 + three-segment JWS immediately —
            // the packaged adjudication gets a genuine Allow and the bind couples (the
            // GracefulShutdownRacesTest IMMEDIATE-answer idiom).
            idp = TokenIdpStandIn.allowIdp(
                    new CountDownLatch(1), new CountDownLatch(1), false, "packaged-smoke-idp");
            int bindPort = RelayTestFixtures.freePort();
            int metricsPort = RelayTestFixtures.freePort();
            Path stdout = dir.resolve("packaged-stdout.log");
            Path stderr = dir.resolve("packaged-stderr.log");
            List<String> command = new ArrayList<>();
            command.add(javaBin);
            command.addAll(jvmFlags);
            command.add("-jar");
            command.add(BOOT_JAR.toString());
            command.addAll(cellArgs(idp, smsc.port(), bindPort, metricsPort));
            process = new ProcessBuilder(command)
                    .redirectOutput(stdout.toFile())
                    .redirectError(stderr.toFile())
                    .start();
            return new Rig(smsc, idp, process, stdout, stderr, bindPort, metricsPort);
        } catch (RuntimeException | Error | IOException e) {
            // a rig that fails to build must not strand what it already created (the
            // GracefulShutdownRacesTest rig rule) — the caller's try-with-resources never engages
            // when launch() never returns.
            if (process != null) {
                process.destroyForcibly();
            }
            if (idp != null) {
                idp.stop(0);
            }
            smsc.close();
            throw e;
        }
    }

    /**
     * The packaged reverse-B cell as run args (args outrank application.yml — the
     * {@code MetricsEndpointTest} run-args lesson). The yml supplies everything else: the TLS
     * lists, the 4s adjudication deadline, the 30s idle window, the memory trio, and
     * {@code budget-check: fail}.
     *
     * <p>NO {@code companion.memory.*} keys, deliberately: the AD-30 interlock rides the yml
     * DEFAULTS against the constant's {@code -XX:MaxDirectMemorySize} ("assert it in the smoke —
     * do not fork yml"); overriding the trio here would fork the derivation and the boot would
     * pass trivially, proving nothing. The SHORT drain deadline (2s, an arg) keeps the SIGTERM
     * walk quick — the deadline the drain WARN names on the asserted line.
     */
    private List<String> cellArgs(HttpsServer idp, int smscPort, int bindPort, int metricsPort)
            throws IOException {
        Path clientSecret = Files.writeString(dir.resolve("oidc-client-secret"), "packaged-smoke-secret\n");
        Path idpTrustStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        return List.of(
                "--companion.bind.host=127.0.0.1",
                "--companion.bind.port=" + bindPort,
                "--companion.metrics.port=" + metricsPort,
                "--companion.shutdown.drain-timeout=2s",
                "--companion.reverse.mode-b.smsc.host=127.0.0.1",
                "--companion.reverse.mode-b.smsc.port=" + smscPort,
                "--companion.reverse.mode-b.acknowledged=true",
                "--companion.reverse.mode-b.oidc.provider-url=" + TokenIdpStandIn.realmBase(idp),
                "--companion.reverse.mode-b.oidc.client-id=smpp-client-confidential",
                "--companion.reverse.mode-b.oidc.client-secret-path=" + clientSecret,
                "--companion.reverse.mode-b.oidc.trust-store.path=" + idpTrustStore,
                "--companion.reverse.mode-b.oidc.trust-store.password=" + RelayTestFixtures.IDP_STORE_PASSWORD,
                "--companion.reverse.mode-b.oidc.timeout=4s",
                "--companion.reverse.mode-b.oidc.max-in-flight=64");
    }

    // ── probes and pinned wire literals ───────────────────────────────────────────────────────

    /**
     * Bounded poll for the boot summary on the captured stdout, failing FAST (with the captured
     * output) if the child dies first — a refused boot must surface its own refusal text, never a
     * 45s wait.
     */
    private static void awaitStartupSummary(Rig rig) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(BOOT_DEADLINE_MILLIS);
        while (!output(rig.stdout).contains(STARTUP_SUMMARY_MARKER)) {
            if (!rig.process.isAlive()) {
                fail("the packaged process exited (code " + rig.process.exitValue() + ") before "
                        + "startup_summary — stdout: <" + output(rig.stdout) + ">, stderr: <"
                        + output(rig.stderr) + ">");
            }
            if (System.nanoTime() > deadline) {
                fail("no startup_summary within " + BOOT_DEADLINE_MILLIS + "ms — stdout so far: <"
                        + output(rig.stdout) + ">, stderr: <" + output(rig.stderr) + ">");
            }
            Thread.sleep(100);
        }
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

    /**
     * Lenient file read: a poll can land mid-write on a truncated UTF-8 tail (the JSON messages
     * carry em-dashes), and {@code new String(bytes, UTF_8)} REPLACES a malformed tail with U+FFFD
     * instead of throwing — the marker search is unaffected. After a process exit the file is
     * complete and the read is exact. Checked I/O is wrapped so the read can ride inside
     * {@code fail(...)} diagnostics.
     */
    private static String output(Path file) {
        try {
            return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    /** The read-only /metrics scrape through a raw loopback socket (the MetricsEndpointTest idiom). */
    private static String scrape(int port) throws IOException {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(get("/metrics").getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = socket.getInputStream().read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    private static String get(String path) {
        return "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    }

    /** An OPAQUE non-bind PDU carrying an ASCII tag body (never parsed — AD-3; the tag is the probe). */
    private static byte[] opaquePdu(int commandId, int sequence, String tag) {
        byte[] body = RelayTestFixtures.ascii(tag);
        return RelayTestFixtures.assemble(commandId, 0, sequence, body.length, out -> out.put(body));
    }

    /** The pinned ROK bind_resp contract, asserted on LITERALS (independent of production constants). */
    private static void assertRokBindResp(byte[] resp, int expectedSequence) {
        java.nio.ByteBuffer header = java.nio.ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the resp's command_length covers the whole PDU").isEqualTo(resp.length);
        assertThat(commandId).as("bind_transceiver answered by bind_transceiver_resp")
                .isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(commandStatus)
                .as("ESME_ROK — the packaged chain coupled (ROPC Allow → egress dial → mock ROK)")
                .isZero();
        assertThat(sequence).as("the resp answers the request's sequence_number").isEqualTo(expectedSequence);
    }
}
