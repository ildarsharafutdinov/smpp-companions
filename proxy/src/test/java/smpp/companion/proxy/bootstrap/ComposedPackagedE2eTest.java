package smpp.companion.proxy.bootstrap;

import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpsServer;

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

import smpp.companion.proxy.relay.MockSmsc;
import smpp.companion.proxy.testsupport.ComposedJourney;
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.testsupport.TokenIdpStandIn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static smpp.companion.proxy.testsupport.ComposedJourney.BIND_ACCEPT;
import static smpp.companion.proxy.testsupport.ComposedJourney.BIND_REJECT;
import static smpp.companion.proxy.testsupport.ComposedJourney.BIND_TRANSCEIVER_RESP;
import static smpp.companion.proxy.testsupport.ComposedJourney.DELIVER_SM_RESP;
import static smpp.companion.proxy.testsupport.ComposedJourney.DRAIN_DEADLINE_TEXT;
import static smpp.companion.proxy.testsupport.ComposedJourney.DRAIN_FORCE_CLOSE_MARKER;
import static smpp.companion.proxy.testsupport.ComposedJourney.ESME_RBINDFAIL;
import static smpp.companion.proxy.testsupport.ComposedJourney.LOOPBACK;
import static smpp.companion.proxy.testsupport.ComposedJourney.MODE_A_BANNER;
import static smpp.companion.proxy.testsupport.ComposedJourney.MODE_B_BANNER;
import static smpp.companion.proxy.testsupport.ComposedJourney.PASSWORD;
import static smpp.companion.proxy.testsupport.ComposedJourney.STARTUP_SUMMARY;
import static smpp.companion.proxy.testsupport.ComposedJourney.SUBMIT_SM;
import static smpp.companion.proxy.testsupport.ComposedJourney.SYSTEM_ID;
import static smpp.companion.proxy.testsupport.ComposedJourney.assertHeader;
import static smpp.companion.proxy.testsupport.ComposedJourney.assertHeaderKnownSequence;
import static smpp.companion.proxy.testsupport.ComposedJourney.awaitScrape;
import static smpp.companion.proxy.testsupport.ComposedJourney.bindPortField;
import static smpp.companion.proxy.testsupport.ComposedJourney.bodyOf;
import static smpp.companion.proxy.testsupport.ComposedJourney.deliverSmPdu;
import static smpp.companion.proxy.testsupport.ComposedJourney.dlrListener;
import static smpp.companion.proxy.testsupport.ComposedJourney.expectedBindBody;
import static smpp.companion.proxy.testsupport.ComposedJourney.expectedSubmitBody;
import static smpp.companion.proxy.testsupport.ComposedJourney.firstLineContaining;
import static smpp.companion.proxy.testsupport.ComposedJourney.metricsPortField;
import static smpp.companion.proxy.testsupport.ComposedJourney.output;

/**
 * Story 6.2 T3 &mdash; <b>E2E-001, the packaged JAR rung</b>: the SAME composed journey as the
 * in-JVM rung ({@code ComposedChainE2eTest}) on the DEPLOY shape &mdash; TWO real {@code java -jar}
 * SUBPROCESSES of the one boot jar ({@code forward.mode-c} + {@code reverse.mode-c} per the
 * as-built [B] topology), launched under the ONE operator JVM-flag contract ({@code
 * PackagedBootSmokeTest.OPERATOR_JVM_FLAGS} &equiv; the Docker ENTRYPOINT &equiv; the flag-contract
 * page &mdash; never a third set), with every secret a FILE PATH out of a temp dir (AD-18/DEP-1)
 * and the satellites ({@link MockSmsc} + the TLS token stand-in) on this JVM's loopback. This is
 * the spine's AD-24 letter &mdash; real Spring Boot processes via the deploy-time contract &mdash;
 * and what makes the DEP-1/REL-3 claims honest.
 *
 * <p><b>Why hand-built cell args, not {@code TestCompanionConfigs}:</b> the {@code
 * PackagedBootSmokeTest} javadoc's reasoning, followed not fought &mdash; the runner factories
 * bake the minimal 1/1/1.0 memory trio and a shared stand-in provider-url, both wrong for this
 * boot: the children run under the contract's {@code -XX:MaxDirectMemorySize=6442450944}, so the
 * SHIPPED yml trio (64 &times; 1024 &times; 1.5) is the honest budget and no {@code
 * companion.memory.*} key rides the launch (the AD-30 no-fork interlock is DEPLOY-015's packaged
 * lane, pinned there on the same jar bytes). The args are stated over the same committed fixture
 * MATERIAL ({@code RelayTestFixtures.smppTlsLegs} + the IdP trust store), exactly the {@code
 * PackagedBootSmokeTest.cellArgs} precedent &times;2.
 *
 * <p><b>The journey and its observations are the in-JVM rung's</b> (one home since this story:
 * {@link ComposedJourney}) &mdash; the ALLOW round is jSMPP-driven (COMP-1's independent stack;
 * byte-pinned bodies through both hops and the Mode C mTLS leg), the DENY round is raw-socket
 * (the load-bearing observation is the EXACT on-wire AD-33 collapse) &mdash; with the packaged
 * deltas: the JSON-log surface is each SUBPROCESS's stdout file (the production encoder's own
 * stream), the metrics surface is each instance's host-loopback {@code /metrics} port, and REL-3
 * lands here: <b>SIGTERM to each instance with the pair open &rarr; the ordered AD-22 stream
 * &rarr; exit 143 each</b>.
 *
 * <p><b>The REL-3 asymmetry, stated honestly:</b> the FORWARD is stopped first with the coupled
 * pair live, so its stdout carries the full ordered chain {@code startup_summary < bind_accept <
 * the drain WARN} and exits 143; the reverse's pair died with the forward's drain (the AD-32 pair
 * teardown on the closing mTLS leg), so the REVERSE's walk drains an empty registry &mdash; the
 * documented short-circuit, no WARN &mdash; and exits 143. Both exits are asserted; the WARN only
 * where it is real.
 *
 * <p><b>Mode A disposition (the ratified journey-widening decision, owner 2026-09-13):</b> mode C
 * composed + in-session auth-DENY widened into BOTH packaged shapes by this rung; mode A stays
 * with {@code TlsModesLoopbackE2eTest} (composed mode A at relay altitude) plus the DEPLOY-005
 * structural-sameness argument (one jar, one arg channel, one flag set) &mdash; recorded, not
 * silently ignored.
 *
 * <p>Class-level {@link Timeout} on a separate thread (two fat-jar boots + TLS): a stuck child
 * FAILS the row, never hangs the suite; every poll is bounded with a dead-process fail-fast naming
 * the instance and its own captured output; {@code Rig#close()} is exception-safe and idempotent.
 */
@Tag("integration")
@Tag("e2e")
@Tag("p1")
@Tag("deploy")
@Timeout(value = 300, threadMode = ThreadMode.SEPARATE_THREAD)
@DisplayName("Story 6.2 T3 — E2E-001 (packaged JAR rung): the composed forward.mode-c ↔ "
        + "reverse.mode-c chain as two java -jar subprocesses under the operator flag set, "
        + "file-path secrets, the allow + auth-DENY journeys, and SIGTERM → ordered drain → 143")
class ComposedPackagedE2eTest {

    /**
     * The built boot jar (5.1 T1's pinned main class + stable {@code proxy.jar} name; {@code
     * :proxy:test} dependsOn bootJar and declares it a test INPUT, so this suite can never run
     * against a stale jar).
     */
    private static final Path BOOT_JAR = Path.of("build", "libs", "proxy.jar");

    /** Which token-endpoint behavior the row's reverse adjudicates against (the T2 enum, restated). */
    private enum StandIn {
        /** The immediate-allow arm: a VALID 200 + three-segment JWS → a genuine Allow verdict. */
        ALLOW_200,
        /** The parked-deny arm, hold pre-opened: every token call answers 401 → DenyInvalid. */
        DENY_401
    }

    /** Bounded-poll deadlines (two fat-jar boots on one loaded runner; observations are quick). */
    private static final long BOOT_DEADLINE_MILLIS = 45_000;
    private static final long OBSERVATION_DEADLINE_MILLIS = 10_000;

    /** The SIGTERM drain window: 2s drain deadline + release/quiesce, bounded generously. */
    private static final long EXIT_DEADLINE_MILLIS = 30_000;

    /** Per-invocation temp dir (the fixture PKI, the OIDC secret, the captured subprocess streams). */
    @TempDir
    Path dir;

    // ── row 1: the packaged composed ALLOW round + the REL-3 drain ─────────────────────────────

    @Test
    @DisplayName("packaged composed ALLOW round: a jSMPP ESME binds through forward.jar → mTLS → "
            + "reverse.jar → MockSmsc (ROK end-to-end, the bind frame VERBATIM at the SMSC — AD-14), "
            + "submit_sm byte-intact through both hops, the DLR back on the originating pair, both "
            + "instances' logs+metrics carry the couple; SIGTERM each → ordered drain → 143 (REL-3)")
    void packagedComposedAllowRoundHoldsAndBothInstancesDrainTo143() throws Exception {
        try (Rig rig = launch(StandIn.ALLOW_200)) {
            assertStartupSummaries(rig);

            // (1) ROK at the ESME — observed BY the independent stack (its connectAndBind returns
            // MockSmsc's authored system_id only on ESME_ROK; a deny anywhere in the chain throws).
            SMPPSession esme = new SMPPSession();
            esme.setTransactionTimer(2_000); // MockSmsc answers binds only — the submit's resp wait ends fast
            esme.setEnquireLinkTimer(60_000); // keep the exact PDU-count metrics deterministic
            CountDownLatch dlrReceived = new CountDownLatch(1);
            AtomicReference<DeliverSm> receivedDlr = new AtomicReference<>();
            esme.setMessageReceiverListener(dlrListener(receivedDlr, dlrReceived));
            try {
                try {
                    String smscSystemId = esme.connectAndBind(LOOPBACK, rig.forwardBindPort,
                            new BindParameter(BindType.BIND_TRX, SYSTEM_ID, PASSWORD, "SMPP",
                                    TypeOfNumber.UNKNOWN, NumberingPlanIndicator.UNKNOWN, "",
                                    InterfaceVersion.IF_34),
                            60_000);
                    assertThat(smscSystemId)
                            .as("the ROK bind_resp crossed BOTH packaged proxies and was parsed by "
                                    + "the independent stack")
                            .isEqualTo("SMSC01");
                    assertThat(esme.getSessionState())
                            .as("the jSMPP session is BOUND_TRX — the couple holds at the ESME surface")
                            .isEqualTo(SessionState.BOUND_TRX);
                } catch (IOException | RuntimeException e) {
                    throw new AssertionError("the packaged composed bind never reached ROK at the "
                            + "jSMPP ESME — the journey failed somewhere on forward.jar → mTLS → "
                            + "reverse.jar → adjudication → MockSmsc: " + e + System.lineSeparator()
                            + rig.capturedTail(), e);
                }

                MockSmsc.Session smscSide = rig.smsc.awaitSession(0);

                // (2) AD-14 through two processes + one mTLS leg: the bind body byte-pinned.
                byte[] bindFrame = smscSide.bindFrame();
                assertHeaderKnownSequence(bindFrame, ComposedJourney.BIND_TRANSCEIVER);
                assertThat(bodyOf(bindFrame))
                        .as("the bind body is byte-identical to what the jSMPP ESME serialized "
                                + "(two packaged hops)")
                        .isEqualTo(expectedBindBody());

                // (3) submit_sm byte-intact through both subprocesses (the resp wait ends in the
                // EXPECTED ResponseTimeoutException — the submit hit the wire the instant it was made).
                byte[] tag = RelayTestFixtures.ascii("PACKAGED-COMPOSED-SUBMIT");
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
                        .as("the §4.4.1 submit body crossed ESME → forward.jar → mTLS → "
                                + "reverse.jar → MockSmsc byte-identical")
                        .isEqualTo(expectedSubmitBody(tag));

                // (4) A-1 affinity across TWO PACKAGED proxies: the DLR injected on the ESME's own
                // SMSC session comes back on THAT pair, and the deliver_sm_resp receipt crosses to
                // the SAME session.
                byte[] dlr = deliverSmPdu(0x5A5, "PACKAGED-COMPOSED-DLR");
                smscSide.deliver(dlr);
                assertThat(dlrReceived.await(OBSERVATION_DEADLINE_MILLIS, TimeUnit.MILLISECONDS))
                        .as("the DLR returned on the ORIGINATING pair through both subprocesses")
                        .isTrue();
                assertThat(receivedDlr.get().getShortMessage())
                        .as("the DLR's short_message is byte-equal to the injected payload")
                        .isEqualTo(RelayTestFixtures.ascii("PACKAGED-COMPOSED-DLR"));
                byte[] dlrReceipt = smscSide.awaitPdus(2).get(1);
                assertHeader(dlrReceipt, DELIVER_SM_RESP, 0, 0x5A5);

                // (5) The per-instance METRICS surface: the couple on BOTH (the forward's routed
                // accept; the reverse's off-table unknown counter), one INGRESS fire per PDU each
                // instance read and one EGRESS fire, zero rejects anywhere.
                assertThat(awaitScrape(rig.forwardMetricsPort,
                        "relay_binds_accepted_total{system_id=\"carrierOne\"} 1.0",
                        OBSERVATION_DEADLINE_MILLIS))
                        .contains("relay_pdus_total{direction=\"INGRESS\"} 2.0")
                        .contains("relay_pdus_total{direction=\"EGRESS\"} 1.0")
                        .contains("relay_binds_rejected_total 0.0")
                        .as("Story 8.1 T2: each relayed PDU also recorded its transit (mirrors the "
                                + "PDU counters — the same single fire; timer _count rows render "
                                + "integer, unlike the 1.0 counters)")
                        .contains("relay_pdus_transit_seconds_count{direction=\"INGRESS\"} 2")
                        .contains("relay_pdus_transit_seconds_count{direction=\"EGRESS\"} 1")
                        .as("the forward's AlwaysAllow settle recorded exactly one adjudication "
                                + "(VerifierWiringConfig: forward cells wire the stand-in verifier)")
                        .contains("relay_binds_adjudication_seconds_count 1");
                assertThat(awaitScrape(rig.reverseMetricsPort, "relay_binds_unknown_total 1.0",
                        OBSERVATION_DEADLINE_MILLIS))
                        .contains("relay_pdus_total{direction=\"INGRESS\"} 2.0")
                        .contains("relay_pdus_total{direction=\"EGRESS\"} 1.0")
                        .contains("relay_binds_rejected_total 0.0")
                        .as("Story 8.1 T2: each relayed PDU also recorded its transit (mirrors the "
                                + "PDU counters — the same single fire)")
                        .contains("relay_pdus_transit_seconds_count{direction=\"INGRESS\"} 2")
                        .contains("relay_pdus_transit_seconds_count{direction=\"EGRESS\"} 1")
                        .as("the reverse's ROPC adjudication against the stand-in IdP settled Allow — "
                                + "the couple requires that settle, and the settle funnel records "
                                + "before the egress dial")
                        .contains("relay_binds_adjudication_seconds_count 1");

                // (6) The LOG surface: bind_accept on BOTH subprocess streams, no reject anywhere.
                assertThat(firstLineContaining(output(rig.forwardStdout), BIND_ACCEPT))
                        .as("the forward's couple line names the routed id")
                        .contains("\"system_id\":\"" + SYSTEM_ID + "\"", "\"outcome\":\"coupled\"");
                assertThat(firstLineContaining(output(rig.reverseStdout), BIND_ACCEPT))
                        .as("the reverse's couple line names the same id and carries the couple "
                                + "outcome (the in-JVM rung's both-instance pin)")
                        .contains("\"system_id\":\"" + SYSTEM_ID + "\"", "\"outcome\":\"coupled\"");
                assertThat(output(rig.forwardStdout) + output(rig.reverseStdout))
                        .doesNotContain(BIND_REJECT);

                // (7) REL-3: SIGTERM the FORWARD with the pair OPEN — its walk drains the live pair
                // to the PT2S deadline (the OBS-020 WARN), in order, then exit 143.
                rig.forwardProcess.destroy(); // SIGTERM (Linux)
                assertExits143(rig.forwardProcess, "forward", rig.forwardStdout, rig.forwardStderr);
                String forwardOut = output(rig.forwardStdout);
                int summaryIdx = forwardOut.indexOf(STARTUP_SUMMARY);
                int acceptIdx = forwardOut.indexOf(BIND_ACCEPT);
                int drainIdx = forwardOut.indexOf(DRAIN_FORCE_CLOSE_MARKER);
                assertThat(summaryIdx).as("the boot summary is on the forward's stream").isGreaterThanOrEqualTo(0);
                assertThat(acceptIdx)
                        .as("ordered stream: the couple line follows the startup summary")
                        .isGreaterThan(summaryIdx);
                assertThat(drainIdx)
                        .as("ordered stream: the AD-22 step-3 drain WARN follows the couple line "
                                + "(the pair was live at the signal and was force-closed at the deadline)")
                        .isGreaterThan(acceptIdx);
                assertThat(firstLineContaining(forwardOut, DRAIN_FORCE_CLOSE_MARKER))
                        .as("the drain line is the walk's WARN (OBS-020), naming the 2s deadline "
                                + "this rig configured")
                        .contains("\"level\":\"WARN\"", DRAIN_DEADLINE_TEXT);

                // (8) …then the REVERSE: its pair died with the forward's drain (the AD-32 pair
                // teardown on the closing mTLS leg), so its walk drains an EMPTY registry — the
                // documented short-circuit, no WARN to claim — and still exits a clean 143.
                rig.reverseProcess.destroy();
                assertExits143(rig.reverseProcess, "reverse", rig.reverseStdout, rig.reverseStderr);
                String reverseOut = output(rig.reverseStdout);
                assertThat(reverseOut.indexOf(BIND_ACCEPT))
                        .as("the reverse's own couple line preceded its exit")
                        .isGreaterThan(reverseOut.indexOf(STARTUP_SUMMARY));
                assertThat(reverseOut.indexOf(STARTUP_SUMMARY)).isGreaterThanOrEqualTo(0);
            } finally {
                esme.close(); // AFTER the exit assertions — the pair must stay open into both signals
            }
        }
    }

    // ── row 2: the packaged composed auth-DENY round ──────────────────────────────────────────

    @Test
    @DisplayName("packaged composed auth-DENY round: the stand-in's 401 → ONE header-only "
            + "ESME_RBINDFAIL on the wire then close, NO couple anywhere (no SMSC session, no accept "
            + "line), the rich verdict ONLY in the reverse subprocess's bind_reject line + "
            + "relay_binds_rejected_total — and both instances keep running (fail-closed service)")
    void packagedComposedAuthDenyRoundCollapsesToOneGenericCodeAndNeverCouples() throws Exception {
        try (Rig rig = launch(StandIn.DENY_401)) {
            assertStartupSummaries(rig);
            try (Socket esme = new Socket(LOOPBACK, rig.forwardBindPort)) {
                esme.setSoTimeout(10_000);
                RelayTestFixtures.writePdu(esme, RelayTestFixtures.bindRequest(11, SYSTEM_ID, PASSWORD));

                // ONE generic failure code on the wire (AD-33), verbatim-forwarded by the forward
                // subprocess (RELAY-002c) — 16 octets, then the leg closes.
                byte[] deny = RelayTestFixtures.readPdu(esme);
                assertThat(deny.length).as("header-only construct").isEqualTo(16);
                assertHeader(deny, BIND_TRANSCEIVER_RESP, ESME_RBINDFAIL, 11);
                try {
                    RelayTestFixtures.readPdu(esme);
                    fail("the leg should be gone after the deny");
                } catch (EOFException expected) {
                    // 'bind_resp error, then close' — the composed leg is gone after the deny
                }
            }

            // No couple anywhere: the SMSC leg never opened, and NEITHER subprocess accepted.
            assertThat(rig.smsc.sessions()).as("the denied bind never reached the SMSC").isEmpty();
            assertThat(rig.tokenReceived.await(OBSERVATION_DEADLINE_MILLIS, TimeUnit.MILLISECONDS))
                    .as("the reverse's ROPC exchange really crossed the TLS stand-in (the 401 arm)")
                    .isTrue();

            // The rich verdict — ONLY on the reverse subprocess's stream + reject counter: exactly
            // ONE bind_reject line, carrying the verdict type and the AD-33 status; the forward
            // logged no bind_reject at all (its verifier is the trusted-side stand-in; the deny it
            // forwarded is not a Verdict, AD-27).
            List<String> rejects = output(rig.reverseStdout).lines()
                    .filter(line -> line.contains(BIND_REJECT)).toList();
            assertThat(rejects).as("exactly one bind_reject line, on the reverse").hasSize(1);
            assertThat(rejects.get(0))
                    .contains("\"system_id\":\"" + SYSTEM_ID + "\"", "\"verdict\":\"DenyInvalid\"",
                            "\"bind_resp_command_status\":\"0x0000000D\"");
            assertThat(output(rig.forwardStdout)).doesNotContain(BIND_REJECT, BIND_ACCEPT);

            // The metrics agree: the REVERSE rejected (its counter + the off-table unknown arm), the
            // FORWARD stayed at zero on every couple/reject surface.
            assertThat(awaitScrape(rig.reverseMetricsPort, "relay_binds_rejected_total 1.0",
                    OBSERVATION_DEADLINE_MILLIS))
                    .contains("relay_binds_unknown_total 1.0")
                    .contains("relay_pdus_total{direction=\"INGRESS\"} 0.0");
            assertThat(ComposedJourney.scrape(rig.forwardMetricsPort))
                    .contains("relay_binds_rejected_total 0.0")
                    .contains("relay_binds_accepted_total{system_id=\"carrierOne\"} 0.0")
                    .contains("relay_pdus_total{direction=\"INGRESS\"} 0.0");

            // The deny is a VERDICT, not a crash: both packaged instances stay up (fail-closed
            // service — the next bind would adjudicate again).
            assertThat(rig.forwardProcess.isAlive())
                    .as("the forward subprocess survived the deny round").isTrue();
            assertThat(rig.reverseProcess.isAlive())
                    .as("the reverse subprocess survived the deny round").isTrue();
        }
    }

    // ── the rig: two subprocesses + the loopback satellites ───────────────────────────────────

    /**
     * Everything one row holds: the two {@code java -jar} subprocesses (their captured streams and
     * per-instance ports), the SMSC satellite, the stand-in IdP (with the deny row's token-received
     * latch). {@code close()} is idempotent and exception-safe (the house rule): a failed row must
     * not strand either child JVM, the mock's loop, or the stand-in's executor.
     */
    private static final class Rig implements AutoCloseable {

        final MockSmsc smsc;
        final HttpsServer idp;
        final CountDownLatch tokenReceived;
        final Process forwardProcess;
        final Process reverseProcess;
        final Path forwardStdout;
        final Path forwardStderr;
        final Path reverseStdout;
        final Path reverseStderr;
        final int forwardBindPort;
        final int reverseBindPort;
        final int forwardMetricsPort;
        final int reverseMetricsPort;

        Rig(MockSmsc smsc, HttpsServer idp, CountDownLatch tokenReceived,
                Process reverseProcess, Path reverseStdout, Path reverseStderr, int reverseBindPort,
                int reverseMetricsPort, Process forwardProcess, Path forwardStdout, Path forwardStderr,
                int forwardBindPort, int forwardMetricsPort) {
            this.smsc = smsc;
            this.idp = idp;
            this.tokenReceived = tokenReceived;
            this.reverseProcess = reverseProcess;
            this.reverseStdout = reverseStdout;
            this.reverseStderr = reverseStderr;
            this.reverseBindPort = reverseBindPort;
            this.reverseMetricsPort = reverseMetricsPort;
            this.forwardProcess = forwardProcess;
            this.forwardStdout = forwardStdout;
            this.forwardStderr = forwardStderr;
            this.forwardBindPort = forwardBindPort;
            this.forwardMetricsPort = forwardMetricsPort;
        }

        /** The last lines of BOTH children's streams (fail-fast diagnostics — their own output). */
        String capturedTail() {
            return "reverse stdout tail: <" + tail(output(reverseStdout)) + ">, reverse stderr: <"
                    + output(reverseStderr) + ">, forward stdout tail: <" + tail(output(forwardStdout))
                    + ">, forward stderr: <" + output(forwardStderr) + ">";
        }

        private static String tail(String stream) {
            List<String> lines = stream.lines().toList();
            return String.join(System.lineSeparator(),
                    lines.subList(Math.max(0, lines.size() - 10), lines.size()));
        }

        @Override
        public void close() {
            forwardProcess.destroyForcibly(); // no-op on an already-exited child (the SIGTERM rows)
            reverseProcess.destroyForcibly();
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
     * Launches the composed chain on the deploy shape: satellites first ({@link MockSmsc} + the
     * row's stand-in IdP), the fixture material into {@code dir}, then the REVERSE subprocess
     * (its egress at the mock; its OIDC at the stand-in) and the FORWARD subprocess (its
     * routing[0] at the reverse's port) &mdash; {@code java <OPERATOR_JVM_FLAGS> -jar proxy.jar
     * <cell args>}, both streams redirected to FILES under {@code dir} (redirect-files, not
     * pipes &mdash; a child can never block on an undrained pipe buffer).
     */
    private Rig launch(StandIn standIn) throws IOException, InterruptedException {
        assertThat(BOOT_JAR)
                .as("the boot jar must exist (:proxy:test dependsOn bootJar; the jar is a test input)")
                .isRegularFile();
        String javaBin = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        MockSmsc smsc = MockSmsc.start();
        HttpsServer idp = null;
        Process reverseProcess = null;
        Process forwardProcess = null;
        try {
            CountDownLatch tokenReceived = new CountDownLatch(1);
            idp = switch (standIn) {
                // park=false answers a VALID 200 immediately; the deny arm's hold latch is
                // PRE-OPENED so the parked handler answers 401 without waiting.
                case ALLOW_200 -> TokenIdpStandIn.allowIdp(
                        new CountDownLatch(1), new CountDownLatch(1), false, "composed-jar-allow-idp");
                case DENY_401 -> TokenIdpStandIn.parkedTokenIdp(
                        tokenReceived, new CountDownLatch(0), "composed-jar-deny-idp");
            };

            // The committed SMPP-leg PKI into dir (the reverse's server pair SANs localhost +
            // 127.0.0.1 — the forward's IP-literal dial trusts the chain, AD-20's IP posture).
            RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
            Path clientSecret = Files.writeString(dir.resolve("oidc-client-secret"),
                    "composed-jar-secret\n");
            Path idpTrustStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));

            int reverseBindPort = RelayTestFixtures.freePort();
            int reverseMetricsPort = RelayTestFixtures.freePort();
            Path reverseStdout = dir.resolve("reverse-stdout.log");
            Path reverseStderr = dir.resolve("reverse-stderr.log");
            reverseProcess = new ProcessBuilder(javaCommand(javaBin, reverseArgs(
                    idp, legs, clientSecret, idpTrustStore, smsc.port(), reverseBindPort,
                    reverseMetricsPort)))
                    .redirectOutput(reverseStdout.toFile())
                    .redirectError(reverseStderr.toFile())
                    .start();
            awaitBoot("reverse", reverseProcess, reverseStdout, reverseStderr, reverseBindPort);

            int forwardBindPort = RelayTestFixtures.freePort();
            int forwardMetricsPort = RelayTestFixtures.freePort();
            Path forwardStdout = dir.resolve("forward-stdout.log");
            Path forwardStderr = dir.resolve("forward-stderr.log");
            forwardProcess = new ProcessBuilder(javaCommand(javaBin, forwardArgs(
                    legs, reverseBindPort, forwardBindPort, forwardMetricsPort)))
                    .redirectOutput(forwardStdout.toFile())
                    .redirectError(forwardStderr.toFile())
                    .start();
            awaitBoot("forward", forwardProcess, forwardStdout, forwardStderr, forwardBindPort);

            return new Rig(smsc, idp, tokenReceived,
                    reverseProcess, reverseStdout, reverseStderr, reverseBindPort, reverseMetricsPort,
                    forwardProcess, forwardStdout, forwardStderr, forwardBindPort, forwardMetricsPort);
        } catch (RuntimeException | Error | IOException | InterruptedException e) {
            // the launch-path teardown (the PackagedBootSmokeTest rig rule): the caller's
            // try-with-resources never engages when launch() never returns.
            if (forwardProcess != null) {
                forwardProcess.destroyForcibly();
            }
            if (reverseProcess != null) {
                reverseProcess.destroyForcibly();
            }
            if (idp != null) {
                try {
                    idp.stop(0);
                } catch (Exception ignored) {
                    // best-effort teardown — the launch failure below is the row's signal
                }
            }
            try {
                smsc.close();
            } catch (Exception ignored) {
                // best-effort teardown — the launch failure below is the row's signal
            }
            throw e;
        }
    }

    /** {@code java <the ONE operator flag set> -jar proxy.jar <cell args>} (never a third set). */
    private static List<String> javaCommand(String javaBin, List<String> cellArgs) {
        List<String> command = new ArrayList<>();
        command.add(javaBin);
        command.addAll(PackagedBootSmokeTest.OPERATOR_JVM_FLAGS);
        command.add("-jar");
        command.add(BOOT_JAR.toString());
        command.addAll(cellArgs);
        return command;
    }

    /**
     * The reverse&times;C cell as run args (args outrank application.yml; the yml supplies the TLS
     * lists, the 4s adjudication deadline, the 30s idle window, the memory trio, and {@code
     * budget-check: fail}). NO {@code companion.memory.*} keys, deliberately &mdash; the children
     * run under the contract's {@code -XX:MaxDirectMemorySize} and the yml-default trio is the
     * honest budget (the {@code PackagedBootSmokeTest} reasoning). The SHORT 2s drain deadline
     * keeps the SIGTERM walk quick and is the deadline the drain WARN names.
     */
    private List<String> reverseArgs(HttpsServer idp, RelayTestFixtures.SmppTlsLegs legs,
            Path clientSecret, Path idpTrustStore, int smscPort, int bindPort, int metricsPort) {
        return List.of(
                "--companion.bind.host=127.0.0.1",
                "--companion.bind.port=" + bindPort,
                "--companion.metrics.port=" + metricsPort,
                "--companion.shutdown.drain-timeout=2s",
                "--companion.reverse.mode-c.smsc.host=" + LOOPBACK,
                "--companion.reverse.mode-c.smsc.port=" + smscPort,
                "--companion.reverse.mode-c.server-cert.cert-path=" + legs.reverseServerCert(),
                "--companion.reverse.mode-c.server-cert.key-path=" + legs.reverseServerKey(),
                "--companion.reverse.mode-c.trust-store.path=" + legs.trustStore(),
                "--companion.reverse.mode-c.trust-store.password="
                        + RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD,
                "--companion.reverse.mode-c.oidc.provider-url=" + TokenIdpStandIn.realmBase(idp),
                "--companion.reverse.mode-c.oidc.client-id=smpp-client-confidential",
                "--companion.reverse.mode-c.oidc.client-secret-path=" + clientSecret,
                "--companion.reverse.mode-c.oidc.trust-store.path=" + idpTrustStore,
                "--companion.reverse.mode-c.oidc.trust-store.password="
                        + RelayTestFixtures.IDP_STORE_PASSWORD,
                "--companion.reverse.mode-c.oidc.timeout=4s",
                "--companion.reverse.mode-c.oidc.max-in-flight=64");
    }

    /**
     * The forward&times;C cell as run args: the per-instance client pair presented on every dial,
     * the trust store anchoring the reverse's server cert, and the ONE routing entry at the
     * reverse's live port. NO oidc node exists on the forward (AD-12 amended &mdash; the trusted
     * side carries no OIDC material).
     */
    private List<String> forwardArgs(RelayTestFixtures.SmppTlsLegs legs, int reversePort,
            int bindPort, int metricsPort) {
        return List.of(
                "--companion.bind.host=127.0.0.1",
                "--companion.bind.port=" + bindPort,
                "--companion.metrics.port=" + metricsPort,
                "--companion.shutdown.drain-timeout=2s",
                "--companion.forward.mode-c.client-cert.cert-path=" + legs.forwardClientCert(),
                "--companion.forward.mode-c.client-cert.key-path=" + legs.forwardClientKey(),
                "--companion.forward.mode-c.trust-store.path=" + legs.trustStore(),
                "--companion.forward.mode-c.trust-store.password="
                        + RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD,
                "--companion.forward.mode-c.routing[0].system-id=" + SYSTEM_ID,
                "--companion.forward.mode-c.routing[0].host=" + LOOPBACK,
                "--companion.forward.mode-c.routing[0].port=" + reversePort);
    }

    // ── the boot- and exit-surface waits ──────────────────────────────────────────────────────

    /**
     * Bounded poll for the instance's {@code startup_summary} (its OWN stream, pinned by its own
     * bind port), failing FAST with the child's own refusal if it dies first — a refused boot
     * surfaces its refusal text, never a 45s wait.
     */
    private static void awaitBoot(String instance, Process process, Path stdout, Path stderr,
            int bindPort) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(BOOT_DEADLINE_MILLIS);
        while (!(output(stdout).contains(STARTUP_SUMMARY)
                && output(stdout).contains(bindPortField(bindPort)))) {
            if (!process.isAlive()) {
                fail("the " + instance + " packaged process exited (code " + process.exitValue()
                        + ") before startup_summary — stdout: <" + output(stdout) + ">, stderr: <"
                        + output(stderr) + ">");
            }
            if (System.nanoTime() > deadline) {
                fail("no startup_summary within " + BOOT_DEADLINE_MILLIS + "ms on the " + instance
                        + " packaged process — stdout so far: <" + output(stdout) + ">, stderr: <"
                        + output(stderr) + ">");
            }
            Thread.sleep(100);
        }
    }

    /** The SIGTERM'd instance must exit ON ITS OWN, with code 143 — never a hang, never a crash. */
    private static void assertExits143(Process process, String instance, Path stdout, Path stderr)
            throws InterruptedException {
        assertThat(process.waitFor(EXIT_DEADLINE_MILLIS, TimeUnit.MILLISECONDS))
                .as("the " + instance + " packaged walk must exit on its own — never a hang")
                .withFailMessage("the " + instance + " packaged process did not exit after SIGTERM — "
                        + "stdout so far: <%s>", output(stdout))
                .isTrue();
        assertThat(process.exitValue())
                .as("clean SIGTERM exit on the " + instance + ": 143 = the JVM convention for a "
                        + "hook-completed SIGTERM shutdown (a crash is 1, this rig's forcible kill "
                        + "is 137)")
                .isEqualTo(143);
    }

    /**
     * Both instances reached {@code startup_summary}, distinguished by their OWN bind ports, and
     * the summaries name the composed cells; mode C needs NO ack banner (the A/B warns are the
     * accepted-risk cells, absent here by construction).
     */
    private void assertStartupSummaries(Rig rig) {
        String reverseSummary = output(rig.reverseStdout).lines()
                .filter(line -> line.contains(STARTUP_SUMMARY)
                        && line.contains(bindPortField(rig.reverseBindPort)))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no reverse startup_summary — "
                        + rig.capturedTail()));
        assertThat(reverseSummary)
                .as("the reverse subprocess's boot summary names its cell")
                .contains("\"role\":\"reverse\"", "\"mode\":\"c\"",
                        metricsPortField(rig.reverseMetricsPort));
        String forwardSummary = output(rig.forwardStdout).lines()
                .filter(line -> line.contains(STARTUP_SUMMARY)
                        && line.contains(bindPortField(rig.forwardBindPort)))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no forward startup_summary — "
                        + rig.capturedTail()));
        assertThat(forwardSummary)
                .as("the forward subprocess's boot summary names its cell and routing universe")
                .contains("\"role\":\"forward\"", "\"mode\":\"c\"",
                        metricsPortField(rig.forwardMetricsPort),
                        "\"routing_system_ids\":[\"" + SYSTEM_ID + "\"]");
        assertThat(output(rig.forwardStdout) + output(rig.reverseStdout))
                .as("mode C boots carry no accepted-risk banner")
                .doesNotContain(MODE_A_BANNER, MODE_B_BANNER);
    }
}
