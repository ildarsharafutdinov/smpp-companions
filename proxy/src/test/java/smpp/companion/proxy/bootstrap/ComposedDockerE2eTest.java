package smpp.companion.proxy.bootstrap;

import java.io.EOFException;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.jsmpp.bean.BindType;
import org.jsmpp.bean.DataCodings;
import org.jsmpp.bean.DeliverSm;
import org.jsmpp.bean.ESMClass;
import org.jsmpp.bean.InterfaceVersion;
import org.jsmpp.bean.NumberingPlanIndicator;
import org.jsmpp.bean.RegisteredDelivery;
import org.jsmpp.bean.TypeOfNumber;
import org.jsmpp.extra.ResponseTimeoutException;
import org.jsmpp.extra.SessionState;
import org.jsmpp.session.BindParameter;
import org.jsmpp.session.SMPPSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Testcontainers;

import smpp.companion.proxy.relay.MockSmsc;
import smpp.companion.proxy.testsupport.ComposedJourney;
import smpp.companion.proxy.testsupport.DockerRig;
import smpp.companion.proxy.testsupport.DockerRig.ComposedChain;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static smpp.companion.proxy.testsupport.ComposedJourney.BIND_ACCEPT;
import static smpp.companion.proxy.testsupport.ComposedJourney.BIND_REJECT;
import static smpp.companion.proxy.testsupport.ComposedJourney.BIND_TRANSCEIVER_RESP;
import static smpp.companion.proxy.testsupport.ComposedJourney.DELIVER_SM_RESP;
import static smpp.companion.proxy.testsupport.ComposedJourney.DRAIN_DEADLINE_TEXT;
import static smpp.companion.proxy.testsupport.ComposedJourney.DRAIN_FORCE_CLOSE_MARKER;
import static smpp.companion.proxy.testsupport.ComposedJourney.ESME_RBINDFAIL;
import static smpp.companion.proxy.testsupport.ComposedJourney.MODE_A_BANNER;
import static smpp.companion.proxy.testsupport.ComposedJourney.MODE_B_BANNER;
import static smpp.companion.proxy.testsupport.ComposedJourney.PASSWORD;
import static smpp.companion.proxy.testsupport.ComposedJourney.STARTUP_SUMMARY;
import static smpp.companion.proxy.testsupport.ComposedJourney.SUBMIT_SM;
import static smpp.companion.proxy.testsupport.ComposedJourney.SYSTEM_ID;
import static smpp.companion.proxy.testsupport.ComposedJourney.assertHeader;
import static smpp.companion.proxy.testsupport.ComposedJourney.assertHeaderKnownSequence;
import static smpp.companion.proxy.testsupport.ComposedJourney.bindPortField;
import static smpp.companion.proxy.testsupport.ComposedJourney.bodyOf;
import static smpp.companion.proxy.testsupport.ComposedJourney.deliverSmPdu;
import static smpp.companion.proxy.testsupport.ComposedJourney.dlrListener;
import static smpp.companion.proxy.testsupport.ComposedJourney.expectedBindBody;
import static smpp.companion.proxy.testsupport.ComposedJourney.expectedSubmitBody;
import static smpp.companion.proxy.testsupport.ComposedJourney.metricsPortField;

/**
 * Story 6.2 T3 &mdash; <b>E2E-001, the two-container Docker rung</b>: the composed
 * forward&times;C &harr; reverse&times;C chain as TWO distroless containers of the ONE image
 * ({@link DockerRig#suiteImage} over the {@code :proxy:assembleDockerContext} output &mdash; the
 * same image the 5.2 suites prove), launched through the FOLDED rig ({@code
 * DockerRig.launchComposedModeCChain} &mdash; the BH7 fold's third consumer, exactly what the
 * consolidation existed to serve). This is the DEPLOY-005 parity claim's composed half: the SAME
 * jar bytes, the SAME exec-form ENTRYPOINT flag set, and the SAME Spring run-args channel (the
 * CMD pass-through), now carrying the two-instance Mode C mTLS chain.
 *
 * <p><b>The wiring (the ratified I/O-matrix row, realized by the rig):</b> the ESME lives in this
 * JVM and hits the FORWARD container's PUBLISHED port; the forward container dials the REVERSE's
 * published port via {@code host.testcontainers.internal} with hostname verification ON against
 * the committed {@code docker-host} SAN cert the reverse presents (AD-20 &mdash; the committed
 * PKI re-pointed, never weakened); the reverse ROPC-adjudicates every bind through the TLS stand-in
 * (the REAL {@code RopcBindCredentialVerifier}; the allow arm for row 1, the docker-reachable 401
 * arm for row 2) and dials the host-side {@link MockSmsc} through the same portal.
 *
 * <p><b>The journey and its observations are the in-JVM and JAR rungs'</b> (one home: {@link
 * ComposedJourney}) &mdash; the jSMPP-driven ALLOW round (byte-pinned bodies through both
 * containers and the mTLS leg; the DLR on the originating pair) and the raw-socket DENY round
 * (the exact AD-33 collapse literal) &mdash; with the container deltas: the log surface is each
 * container's docker stdout, the metrics surface is each container's IN-CONTAINER-ONLY scrape
 * ({@code docker exec} of the image's own java against the cp'd probe &mdash; the yml-default
 * 9090 loopback bind, DEPLOY-011's posture), and REL-3's container half: <b>{@code docker stop}
 * per container &rarr; the ordered AD-22 stream &rarr; exit 143</b> (java is PID 1 via the
 * exec-form ENTRYPOINT). The REL-3 asymmetry is the JAR rung's, restated: the FORWARD is stopped
 * first with the pair live (its stdout carries the full ordered chain incl. the drain WARN); the
 * reverse's pair died with the forward's drain, so its walk drains an empty registry and exits
 * 143 without a WARN.
 *
 * <p><b>Mode A disposition (the ratified journey-widening decision, owner 2026-09-13):</b> mode
 * C composed + in-session auth-DENY widened into the Docker shape by this rung; mode A stays with
 * {@code TlsModesLoopbackE2eTest} plus the DEPLOY-005 structural-sameness argument &mdash;
 * recorded, not silently ignored.
 *
 * <p>Gated by {@code disabledWithoutDocker} (daemon-less builds stay GREEN, never a silent
 * green); class-level {@link Timeout} on a separate thread (two container boots + TLS + stops);
 * {@link ComposedChain#close()} is exception-safe and idempotent (the house rule).
 */
@Tag("integration")
@Tag("e2e")
@Tag("p1")
@Tag("deploy")
@Timeout(value = 600, threadMode = ThreadMode.SEPARATE_THREAD)
@Testcontainers(disabledWithoutDocker = true)
@DisplayName("Story 6.2 T3 — E2E-001 (Docker rung): the composed forward.mode-c ↔ reverse.mode-c "
        + "chain as two containers of the one image through the folded rig, the allow + auth-DENY "
        + "journeys, and docker stop → ordered drain → 143")
class ComposedDockerE2eTest {

    /**
     * The image this suite builds and boots &mdash; the SAME assembled context every other Docker
     * suite uses, under this suite's OWN reaper tag (the per-suite image lifecycle the folded rig
     * keeps: {@code t3-suite}/{@code t4-suite} are the 5.2 suites').
     */
    private static final ImageFromDockerfile IMAGE = DockerRig.suiteImage("smpp-proxy:composed-suite");

    /** The yml-default metrics port neither cell overrides (DEPLOY-011: no host key exists). */
    private static final int METRICS_PORT = 9090;

    /** Bounded-poll deadline for the post-boot observations (docker log/exec latency included). */
    private static final long OBSERVATION_DEADLINE_MILLIS = 10_000;

    /** Per-invocation temp dir (the two cells' mounted secret material). */
    @TempDir
    Path dir;

    // ── row 1: the composed Docker ALLOW round + the REL-3 stops ──────────────────────────────

    @Test
    @DisplayName("docker composed ALLOW round: a jSMPP ESME binds through the forward container's "
            + "published port → portal mTLS → the reverse container → the host MockSmsc (ROK "
            + "end-to-end, the bind frame VERBATIM at the SMSC — AD-14), submit_sm byte-intact, "
            + "the DLR back on the originating pair, both containers' logs+in-container metrics "
            + "carry the couple; docker stop each → ordered drain → 143 (REL-3)")
    void dockerComposedAllowRoundHoldsAndBothContainersStopTo143() throws Exception {
        try (ComposedChain chain = DockerRig.launchComposedModeCChain(
                IMAGE, dir, false, "composed-docker-allow-idp")) {
            DockerRig reverse = chain.reverse;
            DockerRig forward = chain.forward;
            reverse.awaitStartupSummary();
            forward.awaitStartupSummary();
            assertStartupSummaries(reverse, forward);

            // (1) ROK at the ESME — observed BY the independent stack, through the published port.
            SMPPSession esme = new SMPPSession();
            esme.setTransactionTimer(2_000); // MockSmsc answers binds only — the submit's resp wait ends fast
            esme.setEnquireLinkTimer(60_000); // keep the exact PDU-count metrics deterministic
            CountDownLatch dlrReceived = new CountDownLatch(1);
            AtomicReference<DeliverSm> receivedDlr = new AtomicReference<>();
            esme.setMessageReceiverListener(dlrListener(receivedDlr, dlrReceived));
            try {
                try {
                    String smscSystemId = esme.connectAndBind(
                            forward.container().getHost(),
                            forward.container().getMappedPort(forward.bindPort()),
                            new BindParameter(BindType.BIND_TRX, SYSTEM_ID, PASSWORD, "SMPP",
                                    TypeOfNumber.UNKNOWN, NumberingPlanIndicator.UNKNOWN, "",
                                    InterfaceVersion.IF_34),
                            60_000);
                    assertThat(smscSystemId)
                            .as("the ROK bind_resp crossed BOTH containers (the forward's published "
                                    + "port, the mTLS leg, the reverse's adjudication + SMSC dial) "
                                    + "and was parsed by the independent stack")
                            .isEqualTo("SMSC01");
                    assertThat(esme.getSessionState()).isEqualTo(SessionState.BOUND_TRX);
                } catch (IOException | RuntimeException e) {
                    throw new AssertionError("the containerized composed bind never reached ROK at "
                            + "the jSMPP ESME — the journey failed somewhere on forward → portal "
                            + "mTLS → reverse → adjudication → MockSmsc: " + e
                            + System.lineSeparator() + "reverse logs: <" + reverse.stdout()
                            + System.lineSeparator() + ">, forward logs: <" + forward.stdout() + ">",
                            e);
                }

                MockSmsc.Session smscSide = reverse.smsc().awaitSession(0);

                // (2) AD-14 through two containers + the portal mTLS leg: the bind body byte-pinned.
                byte[] bindFrame = smscSide.bindFrame();
                assertHeaderKnownSequence(bindFrame, ComposedJourney.BIND_TRANSCEIVER);
                assertThat(bodyOf(bindFrame))
                        .as("the bind body is byte-identical to what the jSMPP ESME serialized "
                                + "(two container hops)")
                        .isEqualTo(expectedBindBody());

                // (3) submit_sm byte-intact through both containers (the resp wait ends in the
                // EXPECTED ResponseTimeoutException — the submit hit the wire the instant it was made).
                byte[] tag = RelayTestFixtures.ascii("DOCKER-COMPOSED-SUBMIT");
                try {
                    esme.submitShortMessage("",
                            TypeOfNumber.UNKNOWN, NumberingPlanIndicator.UNKNOWN, "1111",
                            TypeOfNumber.UNKNOWN, NumberingPlanIndicator.UNKNOWN, "9999",
                            new ESMClass((byte) 0), (byte) 0, (byte) 0, "", "",
                            new RegisteredDelivery((byte) 0), (byte) 0, DataCodings.ZERO, (byte) 0, tag);
                    fail("submitShortMessage should have ended in the expected ResponseTimeoutException "
                            + "(MockSmsc answers binds only)");
                } catch (ResponseTimeoutException expected) {
                    // the satellite-honesty note: the submit itself is asserted below, at the SMSC
                }
                byte[] submitFrame = smscSide.awaitPdus(1).get(0);
                assertHeaderKnownSequence(submitFrame, SUBMIT_SM);
                assertThat(bodyOf(submitFrame))
                        .as("the §4.4.1 submit body crossed ESME → forward container → portal mTLS "
                                + "→ reverse container → MockSmsc byte-identical")
                        .isEqualTo(expectedSubmitBody(tag));

                // (4) A-1 affinity across TWO CONTAINERS: the DLR injected on the ESME's own SMSC
                // session comes back on THAT pair; the deliver_sm_resp receipt crosses to the
                // SAME session.
                byte[] dlr = deliverSmPdu(0x5D5, "DOCKER-COMPOSED-DLR");
                smscSide.deliver(dlr);
                assertThat(dlrReceived.await(OBSERVATION_DEADLINE_MILLIS, TimeUnit.MILLISECONDS))
                        .as("the DLR returned on the ORIGINATING pair through both containers")
                        .isTrue();
                assertThat(receivedDlr.get().getShortMessage())
                        .isEqualTo(RelayTestFixtures.ascii("DOCKER-COMPOSED-DLR"));
                byte[] dlrReceipt = smscSide.awaitPdus(2).get(1);
                assertHeader(dlrReceipt, DELIVER_SM_RESP, 0, 0x5D5);

                // (5) The per-instance METRICS surface, IN-CONTAINER (the endpoint answers only
                // inside each container, on the literal loopback, via the image's own java): the
                // couple on BOTH, the exact PDU counts, zero rejects anywhere.
                String forwardScrape = inContainerScrape(forward);
                assertThat(forwardScrape)
                        .contains("relay_binds_accepted_total{system_id=\"carrierOne\"} 1.0")
                        .contains("relay_pdus_total{direction=\"INGRESS\"} 2.0")
                        .contains("relay_pdus_total{direction=\"EGRESS\"} 1.0")
                        .contains("relay_binds_rejected_total 0.0");
                String reverseScrape = inContainerScrape(reverse);
                assertThat(reverseScrape)
                        .contains("relay_binds_unknown_total 1.0")
                        .contains("relay_pdus_total{direction=\"INGRESS\"} 2.0")
                        .contains("relay_pdus_total{direction=\"EGRESS\"} 1.0")
                        .contains("relay_binds_rejected_total 0.0");

                // (6) The LOG surface: bind_accept on BOTH containers' stdout, no reject anywhere.
                assertThat(firstAcceptLine(forward))
                        .as("the forward container's couple line names the routed id")
                        .contains("\"system_id\":\"" + SYSTEM_ID + "\"", "\"outcome\":\"coupled\"");
                assertThat(firstAcceptLine(reverse))
                        .as("the reverse container's couple line names the same id")
                        .contains("\"system_id\":\"" + SYSTEM_ID + "\"");
                assertThat(forward.stdout() + reverse.stdout()).doesNotContain(BIND_REJECT);

                // (7) REL-3, container half: docker stop the FORWARD with the pair OPEN — TERM to
                // PID-1 java walks the AD-22 drain (the OBS-020 WARN at the PT2S deadline), in
                // order, then exit 143.
                dockerStop(forward);
                assertThat(forward.awaitContainerExit())
                        .as("clean docker-stop exit on the forward: 143 = the JVM convention for a "
                                + "hook-completed SIGTERM shutdown (java is PID 1 via the exec-form "
                                + "ENTRYPOINT; a shell-form wrapper would strand the walk)")
                        .isEqualTo(143L);
                String forwardOut = forward.stdout();
                int summaryIdx = forwardOut.indexOf(STARTUP_SUMMARY);
                int acceptIdx = forwardOut.indexOf(BIND_ACCEPT);
                int drainIdx = forwardOut.indexOf(DRAIN_FORCE_CLOSE_MARKER);
                assertThat(summaryIdx).as("the boot summary is on the forward's stdout").isGreaterThanOrEqualTo(0);
                assertThat(acceptIdx)
                        .as("ordered stream: the couple line follows the startup summary")
                        .isGreaterThan(summaryIdx);
                assertThat(drainIdx)
                        .as("ordered stream: the AD-22 step-3 drain WARN follows the couple line "
                                + "(the pair was live at the signal and was force-closed at the deadline)")
                        .isGreaterThan(acceptIdx);
                assertThat(forwardOut.lines().filter(line -> line.contains(DRAIN_FORCE_CLOSE_MARKER))
                        .findFirst().orElseThrow())
                        .as("the drain line is the walk's WARN (OBS-020), naming the 2s deadline "
                                + "the rig configured")
                        .contains("\"level\":\"WARN\"", DRAIN_DEADLINE_TEXT);

                // (8) …then the REVERSE: its pair died with the forward's drain (the AD-32 pair
                // teardown on the closing mTLS leg), so its walk drains an EMPTY registry — the
                // documented short-circuit, no WARN to claim — and still exits a clean 143.
                dockerStop(reverse);
                assertThat(reverse.awaitContainerExit())
                        .as("clean docker-stop exit on the reverse")
                        .isEqualTo(143L);
                String reverseOut = reverse.stdout();
                assertThat(reverseOut.indexOf(STARTUP_SUMMARY)).isGreaterThanOrEqualTo(0);
                assertThat(reverseOut.indexOf(BIND_ACCEPT))
                        .as("the reverse's own couple line preceded its exit")
                        .isGreaterThan(reverseOut.indexOf(STARTUP_SUMMARY));
            } finally {
                esme.close(); // AFTER the stop assertions — the pair must stay open into both signals
            }
        }
    }

    // ── row 2: the composed Docker auth-DENY round ────────────────────────────────────────────

    @Test
    @DisplayName("docker composed auth-DENY round: the stand-in's 401 → ONE header-only "
            + "ESME_RBINDFAIL on the wire then close, NO couple anywhere (no SMSC session, no accept "
            + "line), the rich verdict ONLY in the reverse container's bind_reject line + "
            + "relay_binds_rejected_total (in-container scrape)")
    void dockerComposedAuthDenyRoundCollapsesToOneGenericCodeAndNeverCouples() throws Exception {
        try (ComposedChain chain = DockerRig.launchComposedModeCChain(
                IMAGE, dir, true, "composed-docker-deny-idp")) {
            DockerRig reverse = chain.reverse;
            DockerRig forward = chain.forward;
            reverse.awaitStartupSummary();
            forward.awaitStartupSummary();

            // ONE generic failure code on the wire (AD-33), verbatim-forwarded by the forward
            // container — 16 octets, then the leg closes.
            try (java.net.Socket esme = forward.connectLegacy()) {
                RelayTestFixtures.writePdu(esme, RelayTestFixtures.bindRequest(13, SYSTEM_ID, PASSWORD));
                byte[] deny = RelayTestFixtures.readPdu(esme);
                assertThat(deny.length).as("header-only construct").isEqualTo(16);
                assertHeader(deny, BIND_TRANSCEIVER_RESP, ESME_RBINDFAIL, 13);
                try {
                    RelayTestFixtures.readPdu(esme);
                    fail("the leg should be gone after the deny");
                } catch (EOFException expected) {
                    // 'bind_resp error, then close' — the composed leg is gone after the deny
                }
            }

            // No couple anywhere: the SMSC leg never opened, and NEITHER container accepted.
            assertThat(reverse.smsc().sessions()).as("the denied bind never reached the SMSC").isEmpty();
            assertThat(chain.tokenReceived.await(OBSERVATION_DEADLINE_MILLIS, TimeUnit.MILLISECONDS))
                    .as("the reverse's ROPC exchange really crossed the TLS stand-in (the 401 arm)")
                    .isTrue();

            // The rich verdict — ONLY on the reverse container's stdout + reject counter.
            List<String> rejects = reverse.stdout().lines()
                    .filter(line -> line.contains(BIND_REJECT)).toList();
            assertThat(rejects).as("exactly one bind_reject line, on the reverse").hasSize(1);
            assertThat(rejects.get(0))
                    .contains("\"system_id\":\"" + SYSTEM_ID + "\"", "\"verdict\":\"DenyInvalid\"",
                            "\"bind_resp_command_status\":\"0x0000000D\"");
            assertThat(forward.stdout()).doesNotContain(BIND_REJECT, BIND_ACCEPT);

            // The in-container metrics agree: the REVERSE rejected (its counter + the off-table
            // unknown arm), the FORWARD stayed at zero on every couple/reject surface.
            assertThat(inContainerScrape(reverse))
                    .contains("relay_binds_rejected_total 1.0")
                    .contains("relay_binds_unknown_total 1.0")
                    .contains("relay_pdus_total{direction=\"INGRESS\"} 0.0");
            assertThat(inContainerScrape(forward))
                    .contains("relay_binds_rejected_total 0.0")
                    .contains("relay_binds_accepted_total{system_id=\"carrierOne\"} 0.0")
                    .contains("relay_pdus_total{direction=\"INGRESS\"} 0.0");
        }
    }

    // ── the container-surface helpers ─────────────────────────────────────────────────────────

    /** The in-container /metrics scrape via the cp'd probe (the image's own java — no shell). */
    private static String inContainerScrape(DockerRig rig) throws IOException, InterruptedException {
        var scrape = rig.execProbe("scrape", String.valueOf(METRICS_PORT));
        assertThat(scrape.getExitCode())
                .as("the in-container probe scrape succeeded — stderr: <%s>", scrape.getStderr())
                .isZero();
        return scrape.getStdout();
    }

    /** {@code docker stop --timeout 30} (SIGTERM to the PID-1 java). */
    private static void dockerStop(DockerRig rig) {
        rig.container().getDockerClient()
                .stopContainerCmd(rig.container().getContainerId())
                .withTimeout(30)
                .exec();
    }

    /**
     * Both containers reached {@code startup_summary}, distinguished by their OWN bind ports, and
     * the summaries name the composed cells; mode C needs NO ack banner.
     */
    private static void assertStartupSummaries(DockerRig reverse, DockerRig forward) {
        String reverseSummary = reverse.stdout().lines()
                .filter(line -> line.contains(STARTUP_SUMMARY)
                        && line.contains(bindPortField(reverse.bindPort())))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no reverse startup_summary — logs: <"
                        + reverse.stdout() + ">"));
        assertThat(reverseSummary)
                .as("the reverse container's boot summary names its cell (wildcard listener — the "
                        + "published port is the mTLS ingress)")
                .contains("\"role\":\"reverse\"", "\"mode\":\"c\"", "\"smpp_bind_host\":\"0.0.0.0\"",
                        metricsPortField(METRICS_PORT));
        String forwardSummary = forward.stdout().lines()
                .filter(line -> line.contains(STARTUP_SUMMARY)
                        && line.contains(bindPortField(forward.bindPort())))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no forward startup_summary — logs: <"
                        + forward.stdout() + ">"));
        assertThat(forwardSummary)
                .as("the forward container's boot summary names its cell and routing universe")
                .contains("\"role\":\"forward\"", "\"mode\":\"c\"", "\"smpp_bind_host\":\"0.0.0.0\"",
                        metricsPortField(METRICS_PORT),
                        "\"routing_system_ids\":[\"" + SYSTEM_ID + "\"]");
        assertThat(forward.stdout() + reverse.stdout())
                .as("mode C boots carry no accepted-risk banner")
                .doesNotContain(MODE_A_BANNER, MODE_B_BANNER);
    }

    /** The container's first bind_accept line (fails naming its whole stdout if absent). */
    private static String firstAcceptLine(DockerRig rig) {
        return rig.stdout().lines().filter(line -> line.contains(BIND_ACCEPT)).findFirst()
                .orElseThrow(() -> new AssertionError("no bind_accept line — logs: <" + rig.stdout() + ">"));
    }
}
