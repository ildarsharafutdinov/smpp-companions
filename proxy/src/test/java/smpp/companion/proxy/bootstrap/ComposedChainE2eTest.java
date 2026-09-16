package smpp.companion.proxy.bootstrap;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import org.jsmpp.bean.AlertNotification;
import org.jsmpp.bean.BindType;
import org.jsmpp.bean.DataCodings;
import org.jsmpp.bean.DataSm;
import org.jsmpp.bean.DeliverSm;
import org.jsmpp.bean.ESMClass;
import org.jsmpp.bean.InterfaceVersion;
import org.jsmpp.bean.NumberingPlanIndicator;
import org.jsmpp.bean.RegisteredDelivery;
import org.jsmpp.bean.TypeOfNumber;
import org.jsmpp.extra.ProcessRequestException;
import org.jsmpp.extra.ResponseTimeoutException;
import org.jsmpp.extra.SessionState;
import org.jsmpp.session.BindParameter;
import org.jsmpp.session.MessageReceiverListener;
import org.jsmpp.session.SMPPSession;
import org.jsmpp.session.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import com.sun.net.httpserver.HttpsServer;

import smpp.companion.proxy.ProxyCompanionApplication;
import smpp.companion.proxy.config.TestCompanionConfigs;
import smpp.companion.proxy.relay.MockSmsc;
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.testsupport.TokenIdpStandIn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Story 6.2 T2 &mdash; <b>E2E-001, the in-JVM rung</b>: the product's flagship topology run COMPOSED,
 * end to end, as real applications. TWO full {@code SpringApplicationBuilder} boots of
 * {@link ProxyCompanionApplication} in one JVM &mdash; {@code forward.mode-c} + {@code reverse.mode-c}
 * per the as-built [B] topology: the forward DIALS the reverse per SMPP session over the Mode C mTLS
 * leg (the reverse is the listener with its server cert + REQUIRE trust store); the REVERSE &mdash;
 * not the forward &mdash; adjudicates every bind through the REAL {@code RopcBindCredentialVerifier}
 * against the TLS token stand-in (this is what closes the 3.3 close-out ROPC-through-TLS gap); the
 * reverse dials the in-JVM {@link MockSmsc}; a <b>jSMPP 3.0.2 ESME</b> (an independent stack &mdash;
 * COMP-1's interop point, the row's named tooling) drives the legacy leg for the allow round.
 *
 * <p><b>The composed DELTA over {@code TlsModesLoopbackE2eTest}</b> (not a duplicate &mdash; that
 * relay-altitude suite wires harness initializers with the AlwaysAllow stand-in): here the
 * instances are FULL application contexts &mdash; config records binding from run args, the AD-17
 * validator, banners, {@code VerifierWiringConfig}'s REAL adapter selection (ROPC on the reverse,
 * AlwaysAllow on the trusted-side forward), the metrics endpoint &mdash; and adjudication genuinely
 * crosses a real TLS leg (the stand-in IdP's HTTPS token endpoint) inside the composed chain.
 * Every journey names its expected observations per surface: the WIRE (jSMPP/MockSmsc captures, the
 * collapsed deny literals), the JSON-LOG events ({@code startup_summary}/{@code bind_accept}/
 * {@code bind_reject}), and the per-instance METRICS endpoint ({@code /metrics} scrapes on each
 * context's own port).
 *
 * <p><b>Log capture = the production surface</b> (the {@code StructuredLogTest} full-boot idiom):
 * every {@code SpringApplication.run} RE-INITIALIZES logback from the environment, which resets the
 * logger context and would detach any pre-attached appender &mdash; so both instances boot under
 * {@code --logging.config=classpath:logback-spring.xml} with {@code System.out} swapped into an
 * in-memory sink, and the row assertions read the REAL JSON lines (one object per line; the
 * structured kv fields are JSON fields, e.g. {@code "event":"bind_reject"}). That is the same
 * surface the deployed rung (T3) will assert on the subprocess stdout.
 *
 * <p><b>Cell config via {@link TestCompanionConfigs}</b> (the choice the
 * {@code PackagedBootSmokeTest} javadoc frames): the runner-cell factories bake fresh bind/metrics
 * ports per instance (exactly what a two-instance JVM needs) and the minimal 1/1/1.0 memory trio
 * (the capped TEST-JVM direct-memory ceiling needs it &mdash; the AD-30 no-fork interlock pinned to
 * the yml defaults is DEPLOY-015's packaged lane, not this suite's; here the self-check simply
 * passes against the minimal budget). The two per-row retargets ride {@code put()}: the forward's
 * {@code routing[0]} at the reverse's live port, the reverse's OIDC at the row's stand-in. This is
 * also why {@code args()} is public since this suite: run args outrank application.yml.
 *
 * <p><b>ESME flavors, deliberately split:</b> the ALLOW round is driven by the jSMPP client (the
 * independent stack binds, submits, and receives the DLR through its own strict parser &mdash;
 * its {@code connectAndBind} returning MockSmsc's authored {@code SMSC01} system_id IS the
 * ROK-at-the-ESME observation). The DENY and REQUIRE-negative rounds use the raw-socket client:
 * their load-bearing observation is the EXACT on-wire collapse (a 16-octet header-only
 * {@code ESME_RBINDFAIL} then close), which jSMPP surfaces only as a generic
 * {@code IOException("Receive negative bind response")} &mdash; the substitution is recorded here
 * and rides the E2E-001 marker (jSMPP stays on the path via the allow round).
 *
 * <p><b>Satellite honesty:</b> {@link MockSmsc} answers BINDS only (always-ROK, the story's
 * Never-list) &mdash; so the jSMPP {@code submit_sm} gets no {@code submit_sm_resp} and
 * {@code submitShortMessage} ends in {@link ResponseTimeoutException} after the transaction timer.
 * That timeout is EXPECTED and caught: the submit itself hit the wire the moment the call was made
 * (what the row asserts byte-intact at the SMSC), and the DLR round-trip never depends on it.
 *
 * <p>Class-level {@link Timeout} on a separate thread: a stuck boot, dial, or child socket must
 * FAIL a row, never hang the suite. All polls are bounded with fail-fast diagnostics naming the
 * failing hop and the instances' own captured output.
 */
@Tag("integration")
@Tag("e2e")
@Tag("p1")
@Timeout(value = 300, threadMode = ThreadMode.SEPARATE_THREAD)
@DisplayName("Story 6.2 T2 — E2E-001 (in-JVM rung): the composed forward.mode-c ↔ reverse.mode-c "
        + "chain on two real application contexts, real ROPC adjudication over the TLS stand-in, "
        + "a jSMPP ESME, and the in-JVM MockSmsc")
class ComposedChainE2eTest {

    // ── the pinned wire contract (LITERALS — independent of the production constants) ─────────

    private static final int BIND_TRANSCEIVER = 0x00000009;
    private static final int BIND_TRANSCEIVER_RESP = 0x80000009;
    /** SMPP 3.4 §5.1.3 — the ONE generic bind-failure status every proxy-side denial collapses to (AD-33). */
    private static final int ESME_RBINDFAIL = 0x0000000D;
    private static final int SUBMIT_SM = 0x00000004;
    private static final int DELIVER_SM = 0x00000005;
    private static final int DELIVER_SM_RESP = 0x80000005;

    /** One routed system_id — the forward's routing table carries exactly this entry. */
    private static final String SYSTEM_ID = "carrierOne";
    private static final String PASSWORD = "pw123456";

    /** Literal-to-literal (never the loopback InetAddress) against the literal-bound listeners. */
    private static final String LOOPBACK = "127.0.0.1";

    // ── the pinned JSON-log event markers (fields on the production encoder's lines) ──────────

    private static final String STARTUP_SUMMARY = "\"event\":\"startup_summary\"";
    private static final String BIND_ACCEPT = "\"event\":\"bind_accept\"";
    private static final String BIND_REJECT = "\"event\":\"bind_reject\"";
    private static final String MODE_A_BANNER = "MODE A (one-way TLS) is ACTIVE";
    private static final String MODE_B_BANNER = "MODE B (plaintext) is ACTIVE";

    /**
     * Boots BOTH contexts under the PRODUCTION logging config (the {@code StructuredLogTest}
     * full-boot idiom): the boot's logback re-initialization then writes the real JSON lines onto
     * the swapped {@code System.out} instead of the tier's plain {@code logback-test.xml} console.
     */
    private static final String PRODUCTION_LOGGING_CONFIG = "classpath:logback-spring.xml";

    /** Bounded-poll deadlines (generous for a loaded CI runner driving two boots). */
    private static final long BOOT_DEADLINE_MILLIS = 45_000;
    private static final long OBSERVATION_DEADLINE_MILLIS = 10_000;

    /** The swapped-stdout sink for BOTH instances' JSON lines (one JVM, two contexts). */
    private final ByteArrayOutputStream stdoutSink = new ByteArrayOutputStream();
    private PrintStream originalOut;

    @BeforeEach
    void swapStdout() {
        originalOut = System.out;
        System.setOut(new PrintStream(stdoutSink, true, StandardCharsets.UTF_8));
    }

    @AfterEach
    void restoreStdout() {
        System.setOut(originalOut);
    }

    // ── row 1: the composed ALLOW round ───────────────────────────────────────────────────────

    @Test
    @DisplayName("composed ALLOW round: a jSMPP ESME binds through forward → mTLS → reverse → "
            + "MockSmsc (ROK end-to-end, the bind frame VERBATIM at the SMSC — AD-14), submit_sm "
            + "byte-intact through both hops, the DLR back on the originating pair; bind_accept on "
            + "BOTH instances' logs and metrics")
    void composedAllowRoundHoldsAcrossBothRealInstances() throws Exception {
        try (ComposedRig rig = bootComposedChain(dir, StandIn.ALLOW_200, null, null)) {
            assertStartupSummaries(rig);

            // (1) ROK at the ESME — observed BY the independent stack: connectAndBind returns the
            // bind_resp's system_id (MockSmsc's authored "SMSC01") and only reaches BOUND_TRX on
            // ESME_ROK; a deny anywhere in the chain throws here, fail-fast with the captured tail.
            SMPPSession esme = new SMPPSession();
            esme.setTransactionTimer(2_000); // MockSmsc answers binds only — the submit's resp wait ends fast
            CountDownLatch dlrReceived = new CountDownLatch(1);
            AtomicReference<DeliverSm> receivedDlr = new AtomicReference<>();
            esme.setMessageReceiverListener(dlrListener(receivedDlr, dlrReceived));
            try {
                String smscSystemId = esme.connectAndBind(LOOPBACK, rig.forwardBindPort,
                        new BindParameter(BindType.BIND_TRX, SYSTEM_ID, PASSWORD, "SMPP",
                                TypeOfNumber.UNKNOWN, NumberingPlanIndicator.UNKNOWN, "",
                                InterfaceVersion.IF_34),
                        60_000);
                assertThat(smscSystemId)
                        .as("the ROK bind_resp crossed BOTH proxies and was parsed by the "
                                + "independent stack (MockSmsc's authored system_id, verbatim-relayed)")
                        .isEqualTo("SMSC01");
                assertThat(esme.getSessionState())
                        .as("the jSMPP session is BOUND_TRX — the couple holds at the ESME surface")
                        .isEqualTo(SessionState.BOUND_TRX);
            } catch (IOException | RuntimeException e) {
                throw new AssertionError("the composed bind never reached ROK at the jSMPP ESME — "
                        + "the journey failed somewhere on forward → mTLS → reverse → adjudication → "
                        + "MockSmsc: " + e + System.lineSeparator() + capturedTail(), e);
            }

            MockSmsc.Session smscSide = rig.smsc.awaitSession(0);
            try {
                // (2) AD-14, byte-pinned at the SMSC: jSMPP's bind serialization is deterministic
                // (DefaultComposer.bind), so the ENTIRE body is pinned against a hand-built
                // expectation of exactly what the ESME was told to send — any mutation by EITHER
                // proxy of any bind field (or of the framing) fails here.
                byte[] bindFrame = smscSide.bindFrame();
                assertHeaderKnownSequence(bindFrame, BIND_TRANSCEIVER);
                assertThat(bodyOf(bindFrame))
                        .as("AD-14 through TWO hops + one mTLS leg: the bind body is byte-identical "
                                + "to what the jSMPP ESME serialized")
                        .isEqualTo(expectedBindBody());

                // (3) submit_sm byte-intact through both hops. The resp wait ends in the EXPECTED
                // ResponseTimeoutException (MockSmsc answers binds only — the Never-list); the
                // submit hit the wire the instant the call was made.
                byte[] tag = RelayTestFixtures.ascii("COMPOSED-SUBMIT");
                assertThatThrownBy(() -> esme.submitShortMessage("",
                        TypeOfNumber.UNKNOWN, NumberingPlanIndicator.UNKNOWN, "1111",
                        TypeOfNumber.UNKNOWN, NumberingPlanIndicator.UNKNOWN, "9999",
                        new ESMClass((byte) 0), (byte) 0, (byte) 0, "", "",
                        new RegisteredDelivery((byte) 0), (byte) 0, DataCodings.ZERO, (byte) 0, tag))
                        .as("MockSmsc programs binds only — the submit_sm_resp never comes and the "
                                + "transaction timer ends the wait (the submit itself is asserted below)")
                        .isInstanceOf(ResponseTimeoutException.class);
                byte[] submitFrame = smscSide.awaitPdus(1).get(0);
                assertHeaderKnownSequence(submitFrame, SUBMIT_SM);
                assertThat(bodyOf(submitFrame))
                        .as("the §4.4.1 submit body crossed ESME → forward → mTLS → reverse → "
                                + "MockSmsc byte-identical (jSMPP's deterministic serialization)")
                        .isEqualTo(expectedSubmitBody(tag));

                // (4) A-1 affinity across TWO proxies: the DLR injected on the ESME's own SMSC
                // session comes back on THAT pair — observed at the ESME surface (the jSMPP
                // listener on the bound session, through jSMPP's strict parser), and the receipt
                // (deliver_sm_resp) crosses back to the SAME SMSC session.
                byte[] dlr = deliverSmPdu(0x777, "COMPOSED-DLR-FOR-ESME");
                smscSide.deliver(dlr);
                assertThat(dlrReceived.await(OBSERVATION_DEADLINE_MILLIS, TimeUnit.MILLISECONDS))
                        .as("the DLR returned on the ORIGINATING pair (through the reverse, the "
                                + "mTLS leg, and the forward, parsed by the ESME's own stack)")
                        .isTrue();
                assertThat(receivedDlr.get().getShortMessage())
                        .as("the DLR's short_message is byte-equal to the injected payload")
                        .isEqualTo(RelayTestFixtures.ascii("COMPOSED-DLR-FOR-ESME"));
                byte[] dlrReceipt = smscSide.awaitPdus(2).get(1);
                assertHeader(dlrReceipt, DELIVER_SM_RESP, 0, 0x777);

                // (5) The per-instance METRICS surface: the couple visible on BOTH instances (the
                // forward's labeled accept; the reverse's off-table unknown counter — its table is
                // empty by construction), one INGRESS fire per PDU each instance read (submit +
                // deliver_sm_resp) and one EGRESS fire (the DLR), zero rejects anywhere.
                assertThat(awaitScrape(rig.forwardMetricsPort,
                        "relay_binds_accepted_total{system_id=\"carrierOne\"} 1.0"))
                        .contains("relay_pdus_total{direction=\"INGRESS\"} 2.0")
                        .contains("relay_pdus_total{direction=\"EGRESS\"} 1.0")
                        .contains("relay_binds_rejected_total 0.0");
                assertThat(awaitScrape(rig.reverseMetricsPort, "relay_binds_unknown_total 1.0"))
                        .contains("relay_pdus_total{direction=\"INGRESS\"} 2.0")
                        .contains("relay_pdus_total{direction=\"EGRESS\"} 1.0")
                        .contains("relay_binds_rejected_total 0.0");

                // (6) The LOG surface: bind_accept fired on BOTH instances (each couple unit —
                // the reverse's at the SMSC ROK, the forward's at the relayed ROK), no reject.
                List<String> accepts = awaitLines(BIND_ACCEPT, 2);
                assertThat(accepts)
                        .as("one bind_accept line per instance, both naming the routed id")
                        .allSatisfy(line -> assertThat(line)
                                .contains("\"system_id\":\"" + SYSTEM_ID + "\"", "\"outcome\":\"coupled\""));
                assertThat(capturedLines()).noneMatch(line -> line.contains(BIND_REJECT));
            } finally {
                esme.close(); // close the pair BEFORE the rig: the contexts' walk then drains an empty registry
            }
        }
    }

    // ── row 2: the composed auth-DENY round ───────────────────────────────────────────────────

    @Test
    @DisplayName("composed auth-DENY round: the stand-in's 401 → ONE header-only ESME_RBINDFAIL on "
            + "the wire then close, NO couple anywhere (no SMSC session, no accept line), the rich "
            + "verdict ONLY in the reverse's bind_reject line + relay_binds_rejected_total")
    void composedAuthDenyRoundCollapsesToOneGenericCodeAndNeverCouples() throws Exception {
        try (ComposedRig rig = bootComposedChain(dir, StandIn.DENY_401, null, null)) {
            assertStartupSummaries(rig);
            try (Socket esme = new Socket(LOOPBACK, rig.forwardBindPort)) {
                esme.setSoTimeout(10_000);
                byte[] bind = RelayTestFixtures.bindRequest(7, SYSTEM_ID, PASSWORD);
                RelayTestFixtures.writePdu(esme, bind);

                // ONE generic failure code on the wire (AD-33): the reverse's synthesized collapse,
                // verbatim-forwarded by the forward (RELAY-002c) — 16 octets, then the leg closes.
                byte[] deny = RelayTestFixtures.readPdu(esme);
                assertThat(deny.length).as("header-only construct").isEqualTo(16);
                assertHeader(deny, BIND_TRANSCEIVER_RESP, ESME_RBINDFAIL, 7);
                assertThatThrownBy(() -> RelayTestFixtures.readPdu(esme))
                        .as("'bind_resp error, then close' — the composed leg is gone after the deny")
                        .isInstanceOf(EOFException.class);
            }

            // No couple anywhere: the SMSC leg never opened, and NEITHER instance accepted.
            assertThat(rig.smsc.sessions()).as("the denied bind never reached the SMSC").isEmpty();
            assertThat(rig.tokenReceived.await(OBSERVATION_DEADLINE_MILLIS, TimeUnit.MILLISECONDS))
                    .as("the reverse's ROPC exchange really crossed the TLS stand-in (the 401 arm)")
                    .isTrue();

            // The rich verdict — ONLY on the reverse's log line + reject counter: exactly ONE
            // bind_reject line exists (only the verdict holder fires it), carrying the verdict type
            // and the AD-33 status; the forward logged no bind_reject at all (its verifier is the
            // trusted-side stand-in; the deny it forwarded is not a Verdict, AD-27).
            List<String> rejects = awaitLines(BIND_REJECT, 1);
            assertThat(rejects).hasSize(1);
            assertThat(rejects.get(0))
                    .as("the rich verdict surfaces ONLY here: system_id, the DenyInvalid type "
                            + "(the 401 arm's mapping), and the collapsed wire status")
                    .contains("\"system_id\":\"" + SYSTEM_ID + "\"", "\"verdict\":\"DenyInvalid\"",
                            "\"bind_resp_command_status\":\"0x0000000D\"");
            assertThat(capturedLines()).noneMatch(line -> line.contains(BIND_ACCEPT));

            // The metrics agree: the REVERSE rejected (its counter), the FORWARD stayed at zero on
            // every couple/reject surface (nothing coupled, no Verdict anywhere on the forward).
            assertThat(awaitScrape(rig.reverseMetricsPort, "relay_binds_rejected_total 1.0"))
                    .contains("relay_binds_unknown_total 1.0") // the off-table reject arm (AD-19 bound)
                    .contains("relay_pdus_total{direction=\"INGRESS\"} 0.0");
            assertThat(scrape(rig.forwardMetricsPort))
                    .contains("relay_binds_rejected_total 0.0")
                    .contains("relay_binds_accepted_total{system_id=\"carrierOne\"} 0.0")
                    .contains("relay_pdus_total{direction=\"INGRESS\"} 0.0");
        }
    }

    // ── row 3: the Mode C REQUIRE-negative arm ────────────────────────────────────────────────

    @Test
    @DisplayName("Mode C REQUIRE-negative: the forward.mode-c instance dialing with the FOREIGN-CA "
            + "client pair fails the reverse's REQUIRE handshake — AD-33 collapse at the ESME, no "
            + "SMPP byte anywhere, EGRESS_CONNECT_FAILED on the forward's close taxonomy")
    void modeCRequireNegativeRefusesTheForeignClientCertDial() throws Exception {
        // Materialize the committed PKI first: this row's forward presents the FOREIGN client pair
        // (presented-but-UNANCHORED — chains to foreign-ca, not the fixture CA the reverse's
        // REQUIRE trust store anchors). The in-JVM cert-less/unanchored negatives at relay altitude
        // are TlsModesLoopbackE2eTest's rows; this is the composed full-boot arm.
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        try (ComposedRig rig = bootComposedChain(
                dir, StandIn.ALLOW_200, legs.foreignClientCert(), legs.foreignClientKey())) {
            assertStartupSummaries(rig);
            try (Socket esme = new Socket(LOOPBACK, rig.forwardBindPort)) {
                esme.setSoTimeout(10_000);
                RelayTestFixtures.writePdu(esme, RelayTestFixtures.bindRequest(9, SYSTEM_ID, PASSWORD));

                // The dial fails BELOW SMPP (TLS), so no SMSC response PDU can ever exist — the
                // forward collapses to the SAME generic deny (indistinguishable from
                // verifier-reject by design, AD-33), then closes. Fail-closed, no hang.
                byte[] deny = RelayTestFixtures.readPdu(esme);
                assertThat(deny.length).as("header-only construct").isEqualTo(16);
                assertHeader(deny, BIND_TRANSCEIVER_RESP, ESME_RBINDFAIL, 9);
                assertThatThrownBy(() -> RelayTestFixtures.readPdu(esme))
                        .as("the leg closes after the collapse")
                        .isInstanceOf(EOFException.class);
            }

            // The leg NEVER coupled: no SMPP byte crossed — no SMSC session, no bind decoded on the
            // reverse (its reject counter stays ZERO: nothing became an adjudication), no accept.
            assertThat(rig.smsc.sessions()).isEmpty();
            assertThat(capturedLines())
                    .as("below-SMPP failure: neither a reject (no Verdict) nor an accept (no couple)")
                    .noneMatch(line -> line.contains(BIND_REJECT) || line.contains(BIND_ACCEPT));
            assertThat(scrape(rig.reverseMetricsPort)).contains("relay_binds_rejected_total 0.0");

            // The forward's close taxonomy names the failed egress dial (the T4 hoist: the
            // egress-establishment failure is observed with its real reason on the ingress close).
            assertThat(awaitScrape(rig.forwardMetricsPort,
                    "relay_connections_closed_total{direction=\"INGRESS\",reason=\"EGRESS_CONNECT_FAILED\"} 1.0"))
                    .contains("relay_binds_accepted_total{system_id=\"carrierOne\"} 0.0");
        }
    }

    // ── the rig: two real contexts + the satellites, per row ──────────────────────────────────

    /** Which token-endpoint behavior the row's reverse adjudicates against. */
    private enum StandIn {
        /** The immediate-allow arm: a VALID 200 + three-segment JWS → a genuine Allow verdict. */
        ALLOW_200,
        /** The parked-deny arm, hold pre-opened: every token call answers 401 → DenyInvalid. */
        DENY_401
    }

    /**
     * Everything one row holds: the SMSC satellite, the stand-in IdP (with the deny row's
     * token-received latch), and the TWO application contexts with their per-instance ports.
     * {@code close()} is idempotent and exception-safe (the house rule — a failed row must not
     * strand a context, the mock's loop, or the stand-in's executor).
     */
    private static final class ComposedRig implements AutoCloseable {
        final MockSmsc smsc;
        final HttpsServer idp;
        final CountDownLatch tokenReceived;
        final ConfigurableApplicationContext forward;
        final ConfigurableApplicationContext reverse;
        final int forwardBindPort;
        final int reverseBindPort;
        final int forwardMetricsPort;
        final int reverseMetricsPort;

        ComposedRig(MockSmsc smsc, HttpsServer idp, CountDownLatch tokenReceived,
                ConfigurableApplicationContext forward, ConfigurableApplicationContext reverse,
                int forwardBindPort, int reverseBindPort, int forwardMetricsPort, int reverseMetricsPort) {
            this.smsc = smsc;
            this.idp = idp;
            this.tokenReceived = tokenReceived;
            this.forward = forward;
            this.reverse = reverse;
            this.forwardBindPort = forwardBindPort;
            this.reverseBindPort = reverseBindPort;
            this.forwardMetricsPort = forwardMetricsPort;
            this.reverseMetricsPort = reverseMetricsPort;
        }

        @Override
        public void close() {
            closeQuietly(forward);
            closeQuietly(reverse);
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

        private static void closeQuietly(ConfigurableApplicationContext ctx) {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception ignored) {
                    // teardown best-effort — the walk's own behavior is not this suite's assertion
                }
            }
        }
    }

    /** Per-row temp dir (the PKI material, the OIDC secret, the IdP trust store). */
    @TempDir
    Path dir;

    /**
     * Boots the composed chain: satellites first (MockSmsc + the row's stand-in IdP), then the
     * REVERSE context (its egress points at the mock; its OIDC at the stand-in), then the FORWARD
     * (its routing[0] retargeted at the reverse's live port) — each boot fail-fast on refusal
     * naming the instance, with its own captured output (a context that fails to boot is a rig
     * bug, never a hang). {@code foreignClientCert}/{@code foreignClientKey} swap the forward's
     * per-instance client material (the REQUIRE-negative row).
     */
    private ComposedRig bootComposedChain(Path dir, StandIn standIn,
            Path foreignClientCert, Path foreignClientKey) throws IOException {
        MockSmsc smsc = MockSmsc.start();
        HttpsServer idp = null;
        ConfigurableApplicationContext reverse = null;
        ConfigurableApplicationContext forward = null;
        try {
            CountDownLatch tokenReceived = new CountDownLatch(1);
            idp = switch (standIn) {
                // park=false answers a VALID 200 immediately (the GracefulShutdownRacesTest
                // IMMEDIATE-answer idiom); the deny arm's hold latch is PRE-OPENED so the parked
                // handler answers 401 without waiting — the deterministic deny switch.
                case ALLOW_200 -> TokenIdpStandIn.allowIdp(
                        new CountDownLatch(1), new CountDownLatch(1), false, "composed-e2e-allow-idp");
                case DENY_401 -> TokenIdpStandIn.parkedTokenIdp(
                        tokenReceived, new CountDownLatch(0), "composed-e2e-deny-idp");
            };
            int forwardBindPort = RelayTestFixtures.freePort();
            int reverseBindPort = RelayTestFixtures.freePort();
            int forwardMetricsPort = RelayTestFixtures.freePort();
            int reverseMetricsPort = RelayTestFixtures.freePort();

            TestCompanionConfigs reverseCfg = TestCompanionConfigs.reverseC(dir)
                    .put("logging.config", PRODUCTION_LOGGING_CONFIG)
                    .put("companion.bind.port", String.valueOf(reverseBindPort))
                    .put("companion.metrics.port", String.valueOf(reverseMetricsPort))
                    .put("companion.reverse.mode-c.smsc.host", LOOPBACK)
                    .put("companion.reverse.mode-c.smsc.port", String.valueOf(smsc.port()))
                    .put("companion.reverse.mode-c.oidc.provider-url", TokenIdpStandIn.realmBase(idp));
            reverse = bootInstance("reverse", reverseCfg);
            awaitStartupSummary("reverse", reverseBindPort);

            TestCompanionConfigs forwardCfg = TestCompanionConfigs.forwardC(dir)
                    .put("logging.config", PRODUCTION_LOGGING_CONFIG)
                    .put("companion.bind.port", String.valueOf(forwardBindPort))
                    .put("companion.metrics.port", String.valueOf(forwardMetricsPort))
                    .put("companion.forward.mode-c.routing[0].host", LOOPBACK)
                    .put("companion.forward.mode-c.routing[0].port", String.valueOf(reverseBindPort));
            if (foreignClientCert != null) {
                forwardCfg.put("companion.forward.mode-c.client-cert.cert-path", foreignClientCert.toString())
                        .put("companion.forward.mode-c.client-cert.key-path", foreignClientKey.toString());
            }
            forward = bootInstance("forward", forwardCfg);
            awaitStartupSummary("forward", forwardBindPort);

            return new ComposedRig(smsc, idp, tokenReceived, forward, reverse,
                    forwardBindPort, reverseBindPort, forwardMetricsPort, reverseMetricsPort);
        } catch (RuntimeException | Error | IOException e) {
            // the launch-path teardown (the PackagedBootSmokeTest rig rule): the caller's
            // try-with-resources never engages when bootComposedChain never returns.
            if (forward != null) {
                try {
                    forward.close();
                } catch (Exception ignored) {
                    // teardown best-effort — the launch failure below is the row's signal
                }
            }
            if (reverse != null) {
                try {
                    reverse.close();
                } catch (Exception ignored) {
                    // teardown best-effort
                }
            }
            if (idp != null) {
                idp.stop(0);
            }
            smsc.close();
            throw e;
        }
    }

    /** Boots ONE full application context, failing the row with the instance's own refusal. */
    private ConfigurableApplicationContext bootInstance(String instance, TestCompanionConfigs cfg) {
        try {
            return new SpringApplicationBuilder(ProxyCompanionApplication.class)
                    .web(WebApplicationType.NONE)
                    .run(cfg.args());
        } catch (RuntimeException e) {
            throw new AssertionError("the " + instance + " instance refused to boot — its own "
                    + "refusal (a rig bug, never a hang): " + e.getMessage()
                    + System.lineSeparator() + capturedTail(), e);
        }
    }

    // ── row-1 helpers: the jSMPP ESME and the byte-pinned expectations ────────────────────────

    /** The ESME's DLR listener: capture + count down; the client auto-answers deliver_sm_resp ROK. */
    private static MessageReceiverListener dlrListener(AtomicReference<DeliverSm> into, CountDownLatch received) {
        return new MessageReceiverListener() {
            @Override
            public void onAcceptDeliverSm(DeliverSm deliverSm) {
                into.set(deliverSm);
                received.countDown();
            }

            @Override
            public void onAcceptAlertNotification(AlertNotification alertNotification) {
                // not programmed by this row
            }

            @Override
            public org.jsmpp.session.DataSmResult onAcceptDataSm(DataSm dataSm, Session source)
                    throws ProcessRequestException {
                throw new ProcessRequestException("data_sm is not programmed by this row", 0x00000008);
            }
        };
    }

    /**
     * The bind body jSMPP serializes for the row's exact {@link BindParameter} — per its
     * {@code DefaultComposer.bind}: {@code system_id} / {@code password} / {@code system_type}
     * C-octets, then {@code interface_version} (IF_34 = 0x34), {@code addr_ton}/{@code addr_npi}
     * (UNKNOWN = 0/0), and the {@code address_range} C-octet (empty). Pinned byte-for-byte against
     * the frame MockSmsc captured — the AD-14 observation at byte granularity.
     */
    private static byte[] expectedBindBody() {
        return concat(
                cOctet(SYSTEM_ID), cOctet(PASSWORD), cOctet("SMPP"),
                new byte[] {0x34, 0, 0},
                cOctet(""));
    }

    /**
     * The submit_sm body jSMPP serializes for the row's exact {@code submitShortMessage} arguments
     * (per {@code DefaultComposer.submitSm}; the two empty C-octets are the empty
     * schedule/validity strings, then the four single-byte fields — registered_delivery,
     * replace_if_present, data_coding ({@code DataCodings.ZERO} = 0), sm_default_msg_id).
     */
    private static byte[] expectedSubmitBody(byte[] shortMessage) {
        return concat(
                cOctet(""),
                new byte[] {0, 0}, cOctet("1111"),
                new byte[] {0, 0}, cOctet("9999"),
                new byte[] {0, 0, 0},
                cOctet(""), cOctet(""),
                new byte[] {0, 0, 0, 0},
                new byte[] {(byte) shortMessage.length},
                shortMessage);
    }

    /**
     * A WELL-FORMED {@code deliver_sm} (the DLR) in the layout jSMPP 3.0.2's own
     * composer/decomposer pair uses for the PDU (the schedule/validity C-octets and the
     * replace/sm_default octets ride between the fixed fields) — hand-authored raw bytes,
     * independent of the production codec, carrying the ASCII tag probe in {@code short_message}.
     */
    private static byte[] deliverSmPdu(int sequence, String tag) {
        byte[] message = RelayTestFixtures.ascii(tag);
        byte[] body = concat(
                cOctet(""),
                new byte[] {0, 0}, cOctet("SMSC01"),
                new byte[] {0, 0}, cOctet(SYSTEM_ID),
                new byte[] {0x04, 0, 0}, // esm_class 0x04 = SMSC delivery receipt (the DLR shape)
                cOctet(""), cOctet(""),
                new byte[] {0, 0, 0, 0}, // registered_delivery, replace_if_present, data_coding, sm_default_msg_id
                new byte[] {(byte) message.length},
                message);
        return RelayTestFixtures.assemble(DELIVER_SM, 0, sequence, body.length, out -> out.put(body));
    }

    // ── the boot- and observation-surface helpers ─────────────────────────────────────────────

    /**
     * Both instances reached {@code startup_summary} — distinguished by their OWN bind ports — and
     * the summaries name the composed cells; mode C needs NO ack banner (the A/B warns are the
     * accepted-risk cells, absent here by construction).
     */
    private void assertStartupSummaries(ComposedRig rig) {
        String reverseSummary = lineContaining(STARTUP_SUMMARY, bindPortField(rig.reverseBindPort));
        assertThat(reverseSummary)
                .as("the reverse instance's boot summary names its cell")
                .contains("\"role\":\"reverse\"", "\"mode\":\"c\"",
                        metricsPortField(rig.reverseMetricsPort));
        String forwardSummary = lineContaining(STARTUP_SUMMARY, bindPortField(rig.forwardBindPort));
        assertThat(forwardSummary)
                .as("the forward instance's boot summary names its cell and routing universe")
                .contains("\"role\":\"forward\"", "\"mode\":\"c\"",
                        metricsPortField(rig.forwardMetricsPort),
                        "\"routing_system_ids\":[\"" + SYSTEM_ID + "\"]");
        assertThat(capturedLines())
                .as("mode C boots carry no accepted-risk banner")
                .noneMatch(line -> line.contains(MODE_A_BANNER) || line.contains(MODE_B_BANNER));
    }

    /** Bounded poll for the instance's {@code startup_summary} — fails naming the captured tail. */
    private void awaitStartupSummary(String instance, int bindPort) {
        awaitBounded("the " + instance + " instance's startup_summary (smpp_bind_port=" + bindPort + ")",
                () -> capturedLines().stream()
                        .anyMatch(line -> line.contains(STARTUP_SUMMARY)
                                && line.contains(bindPortField(bindPort))),
                BOOT_DEADLINE_MILLIS);
    }

    /**
     * The summary's {@code smpp_bind_port} JSON field for the given port — the field is emitted
     * mid-object (metrics_port follows), so the trailing comma pins the exact number (a prefix
     * port can never match).
     */
    private static String bindPortField(int port) {
        return "\"smpp_bind_port\":" + port + ",";
    }

    /** The summary's {@code metrics_port} JSON field (the LAST field: followed by the brace). */
    private static String metricsPortField(int port) {
        return "\"metrics_port\":" + port;
    }

    /** Bounded poll until at least {@code n} captured lines contain the marker; returns them. */
    private List<String> awaitLines(String marker, int n) {
        awaitBounded(n + " captured line(s) containing <" + marker + ">",
                () -> capturedLines().stream().filter(line -> line.contains(marker)).count() >= n,
                OBSERVATION_DEADLINE_MILLIS);
        return capturedLines().stream().filter(line -> line.contains(marker)).toList();
    }

    /** The first captured line containing BOTH markers (fails naming the whole capture). */
    private String lineContaining(String markerA, String markerB) {
        return capturedLines().stream()
                .filter(line -> line.contains(markerA) && line.contains(markerB))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "no captured line contains both <" + markerA + "> and <" + markerB + "> — capture: "
                                + capturedTail()));
    }

    /** The captured stdout, one JSON line per entry (both instances, in arrival order). */
    private List<String> capturedLines() {
        return stdoutSink.toString(StandardCharsets.UTF_8).lines().toList();
    }

    /** The last 20 captured lines (fail-fast diagnostics — the instance's own output). */
    private String capturedTail() {
        List<String> lines = capturedLines();
        return String.join(System.lineSeparator(),
                lines.subList(Math.max(0, lines.size() - 20), lines.size()));
    }

    private void awaitBounded(String what, BooleanSupplier condition, long timeoutMillis) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out after " + timeoutMillis + "ms waiting for " + what
                        + " — captured tail:" + System.lineSeparator() + capturedTail());
            }
            sleepQuietly(100);
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while awaiting a composed-chain observation", e);
        }
    }

    // ── the per-instance /metrics scrape (the MetricsEndpointTest raw-socket idiom) ───────────

    /** Bounded poll until the instance's scrape contains the needle; returns the final scrape. */
    private String awaitScrape(int metricsPort, String needle) throws IOException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(OBSERVATION_DEADLINE_MILLIS);
        String scrape = scrape(metricsPort);
        while (!scrape.contains(needle)) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("no <" + needle + "> on 127.0.0.1:" + metricsPort
                        + "/metrics within " + OBSERVATION_DEADLINE_MILLIS + "ms — scrape:" + System.lineSeparator()
                        + scrape);
            }
            sleepQuietly(100);
            scrape = scrape(metricsPort);
        }
        return scrape;
    }

    /** The read-only /metrics scrape through a raw loopback socket. */
    private static String scrape(int port) throws IOException {
        try (Socket socket = new Socket(LOOPBACK, port)) {
            socket.setSoTimeout(10_000);
            socket.getOutputStream()
                    .write(("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n"
                            + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
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

    // ── the pinned header/body primitives ─────────────────────────────────────────────────────

    /** The pinned 16-octet header contract: length covers, id/status/sequence exact. */
    private static void assertHeader(byte[] pdu, int commandId, int commandStatus, int sequence) {
        ByteBuffer header = ByteBuffer.wrap(pdu);
        assertThat(header.getInt(0)).as("the command_length covers the whole PDU").isEqualTo(pdu.length);
        assertThat(header.getInt(4)).as("the command_id").isEqualTo(commandId);
        assertThat(header.getInt(8)).as("the command_status").isEqualTo(commandStatus);
        assertThat(header.getInt(12)).as("the sequence_number").isEqualTo(sequence);
    }

    /**
     * The header pin for ESME-AUTHORED frames (jSMPP assigns the sequence from its own session
     * counter): everything exact except the sequence, which is only checked well-formed.
     */
    private static void assertHeaderKnownSequence(byte[] pdu, int commandId) {
        assertHeader(pdu, commandId, 0, headerInt(pdu, 12));
        assertThat(headerInt(pdu, 12)).as("the session-assigned sequence is well-formed").isPositive();
    }

    private static int headerInt(byte[] pdu, int offset) {
        return ByteBuffer.wrap(pdu).getInt(offset);
    }

    private static byte[] bodyOf(byte[] pdu) {
        return Arrays.copyOfRange(pdu, 16, pdu.length);
    }

    /** One NUL-terminated C-octet string (SMPP's fixed-string encoding). */
    private static byte[] cOctet(String s) {
        byte[] bytes = RelayTestFixtures.ascii(s);
        return concat(bytes, new byte[] {0});
    }

    private static byte[] concat(byte[]... parts) {
        return RelayTestFixtures.concat(Arrays.asList(parts));
    }
}
