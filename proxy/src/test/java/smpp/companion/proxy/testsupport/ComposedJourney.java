package smpp.companion.proxy.testsupport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import org.jsmpp.bean.AlertNotification;
import org.jsmpp.bean.DataSm;
import org.jsmpp.bean.DeliverSm;
import org.jsmpp.extra.ProcessRequestException;
import org.jsmpp.session.MessageReceiverListener;
import org.jsmpp.session.Session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Story 6.2 T3 (the journey fold) &mdash; the composed forward&times;C &harr; reverse&times;C chain's
 * SHARED wire/log/scrape primitives: the E2E-001 journeys' pinned literals (command ids, the AD-33
 * collapse code, the routed identity, the JSON event markers), the byte-exact PDU expectations the
 * allow round pins against jSMPP's deterministic serialization, the DLR listener, the header/body
 * asserts, the {@code startup_summary} field builders, and the loopback /metrics scrape. Formerly
 * the private copies of {@code bootstrap/ComposedChainE2eTest} (T2, the in-JVM rung); one home
 * before the THIRD and FOURTH consumers arrive ({@code ComposedPackagedE2eTest}, the JAR rung, and
 * {@code ComposedDockerE2eTest}, the two-container Docker leg) &mdash; the BH7 fold discipline
 * (consolidate into {@code testsupport/} before the next consumer, never after): the three rungs
 * drive the SAME journey, so the wire contract they pin against must live once, not drift in three
 * private copies.
 *
 * <p>Everything here is a pure static over the fixtures' own primitives ({@link RelayTestFixtures}
 * ascii/assemble/concat) &mdash; deliberately independent of the production codec's constants (the
 * hand-authored-bytes discipline: the expectations must fail if EITHER proxy mutates a frame, which
 * a shared constant would mask). Public final class, private constructor (the fixture-fold shape).
 */
public final class ComposedJourney {

    // ── the pinned wire contract (LITERALS — independent of the production constants) ─────────

    /** SMPP 3.4 §5.1.2 — the one bind flavor the composed journey rides. */
    public static final int BIND_TRANSCEIVER = 0x00000009;
    public static final int BIND_TRANSCEIVER_RESP = 0x80000009;

    /**
     * SMPP 3.4 §5.1.3 — the ONE generic bind-failure status every proxy-side denial collapses to
     * (AD-33): the composed deny row asserts this literal, and only this literal, on the wire.
     */
    public static final int ESME_RBINDFAIL = 0x0000000D;

    /** SMPP 3.4 §4.1.2 opaque PDUs the relay carries unparsed (AD-3) — the journey's data plane. */
    public static final int SUBMIT_SM = 0x00000004;
    public static final int DELIVER_SM = 0x00000005;
    public static final int DELIVER_SM_RESP = 0x80000005;

    /** One routed system_id — the forward's routing table carries exactly this entry (AD-29). */
    public static final String SYSTEM_ID = "carrierOne";
    public static final String PASSWORD = "pw123456";

    /**
     * Literal-to-literal loopback (never the loopback InetAddress) against the literal-bound
     * listeners — the BH8 dual-stack trap.
     */
    public static final String LOOPBACK = "127.0.0.1";

    // ── the pinned JSON-log event markers (fields on the production encoder's lines) ──────────

    public static final String STARTUP_SUMMARY = "\"event\":\"startup_summary\"";
    public static final String BIND_ACCEPT = "\"event\":\"bind_accept\"";
    public static final String BIND_REJECT = "\"event\":\"bind_reject\"";
    public static final String MODE_A_BANNER = "MODE A (one-way TLS) is ACTIVE";
    public static final String MODE_B_BANNER = "MODE B (plaintext) is ACTIVE";

    /**
     * The AD-22 step-3 drain WARN's payload marker (OBS-020): the walk force-closed the journey's
     * ONE live pair at the drain deadline. The packaged rungs hold the pair open into the signal
     * so this line is deterministic.
     */
    public static final String DRAIN_FORCE_CLOSE_MARKER = "force-closed 1 live pair(s) as SHUTDOWN_DRAIN";

    /** The drain WARN names the configured deadline — every packaged rig configures PT2S. */
    public static final String DRAIN_DEADLINE_TEXT = "shutdown drain deadline (PT2S) expired";

    private ComposedJourney() {}

    // ── the jSMPP ESME's DLR listener ─────────────────────────────────────────────────────────

    /** The ESME's DLR listener: capture + count down; the client auto-answers deliver_sm_resp ROK. */
    public static MessageReceiverListener dlrListener(AtomicReference<DeliverSm> into, CountDownLatch received) {
        return new MessageReceiverListener() {
            @Override
            public void onAcceptDeliverSm(DeliverSm deliverSm) {
                into.set(deliverSm);
                received.countDown();
            }

            @Override
            public void onAcceptAlertNotification(AlertNotification alertNotification) {
                // not programmed by this journey
            }

            @Override
            public org.jsmpp.session.DataSmResult onAcceptDataSm(DataSm dataSm, Session source)
                    throws ProcessRequestException {
                throw new ProcessRequestException("data_sm is not programmed by this journey", 0x00000008);
            }
        };
    }

    // ── the byte-pinned expectations (jSMPP's deterministic serialization) ────────────────────

    /**
     * The bind body jSMPP serializes for the journey's exact {@code BindParameter} &mdash; per its
     * {@code DefaultComposer.bind}: {@code system_id} / {@code password} / {@code system_type}
     * C-octets, then {@code interface_version} (IF_34 = 0x34), {@code addr_ton}/{@code addr_npi}
     * (UNKNOWN = 0/0), and the {@code address_range} C-octet (empty). Pinned byte-for-byte against
     * the frame MockSmsc captured &mdash; the AD-14 observation at byte granularity, through BOTH
     * hops and the Mode C mTLS leg.
     */
    public static byte[] expectedBindBody() {
        return concat(
                cOctet(SYSTEM_ID), cOctet(PASSWORD), cOctet("SMPP"),
                new byte[] {0x34, 0, 0},
                cOctet(""));
    }

    /**
     * The submit_sm body jSMPP serializes for the journey's exact {@code submitShortMessage}
     * arguments (per {@code DefaultComposer.submitSm}; the two empty C-octets are the empty
     * schedule/validity strings, then the four single-byte fields &mdash; registered_delivery,
     * replace_if_present, data_coding ({@code DataCodings.ZERO} = 0), sm_default_msg_id).
     */
    public static byte[] expectedSubmitBody(byte[] shortMessage) {
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
     * replace/sm_default octets ride between the fixed fields) &mdash; hand-authored raw bytes,
     * independent of the production codec, carrying the ASCII tag probe in {@code short_message}.
     */
    public static byte[] deliverSmPdu(int sequence, String tag) {
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

    // ── the pinned header/body primitives ─────────────────────────────────────────────────────

    /** The pinned 16-octet header contract: length covers, id/status/sequence exact. */
    public static void assertHeader(byte[] pdu, int commandId, int commandStatus, int sequence) {
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
    public static void assertHeaderKnownSequence(byte[] pdu, int commandId) {
        assertHeader(pdu, commandId, 0, headerInt(pdu, 12));
        assertThat(headerInt(pdu, 12)).as("the session-assigned sequence is well-formed").isPositive();
    }

    public static int headerInt(byte[] pdu, int offset) {
        return ByteBuffer.wrap(pdu).getInt(offset);
    }

    public static byte[] bodyOf(byte[] pdu) {
        return Arrays.copyOfRange(pdu, 16, pdu.length);
    }

    /** One NUL-terminated C-octet string (SMPP's fixed-string encoding). */
    public static byte[] cOctet(String s) {
        byte[] bytes = RelayTestFixtures.ascii(s);
        return concat(bytes, new byte[] {0});
    }

    public static byte[] concat(byte[]... parts) {
        return RelayTestFixtures.concat(Arrays.asList(parts));
    }

    // ── the startup_summary field builders (the per-instance identity pins) ───────────────────

    /**
     * The summary's {@code smpp_bind_port} JSON field for the given port &mdash; the field is
     * emitted mid-object (metrics_port follows), so the trailing comma pins the exact number (a
     * prefix port can never match).
     */
    public static String bindPortField(int port) {
        return "\"smpp_bind_port\":" + port + ",";
    }

    /** The summary's {@code metrics_port} JSON field (the LAST field: followed by the brace). */
    public static String metricsPortField(int port) {
        return "\"metrics_port\":" + port;
    }

    // ── stream/file readers and line search ───────────────────────────────────────────────────

    /** The first stream line containing {@code marker} (fails naming the whole stream if absent). */
    public static String firstLineContaining(String stream, String marker) {
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
     * instead of throwing &mdash; the marker search is unaffected. After a process exit the file is
     * complete and the read is exact. Checked I/O is wrapped so the read can ride inside {@code
     * fail(...)} diagnostics.
     */
    public static String output(Path file) {
        try {
            return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ── the per-instance /metrics scrape (the MetricsEndpointTest raw-socket idiom) ───────────

    /** The read-only /metrics scrape through a raw loopback socket. */
    public static String scrape(int port) throws IOException {
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

    /** Bounded poll until the instance's scrape contains the needle; returns the final scrape. */
    public static String awaitScrape(int metricsPort, String needle, long timeoutMillis) throws IOException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        String scrape = scrape(metricsPort);
        while (!scrape.contains(needle)) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("no <" + needle + "> on 127.0.0.1:" + metricsPort
                        + "/metrics within " + timeoutMillis + "ms — scrape:" + System.lineSeparator()
                        + scrape);
            }
            sleepQuietly(100);
            scrape = scrape(metricsPort);
        }
        return scrape;
    }

    /** Bounded poll with a named condition (never an unbounded wait on a composed observation). */
    public static void awaitBounded(String what, BooleanSupplier condition, long timeoutMillis,
            java.util.function.Supplier<String> diagnostics) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out after " + timeoutMillis + "ms waiting for " + what
                        + " — " + diagnostics.get());
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
}
