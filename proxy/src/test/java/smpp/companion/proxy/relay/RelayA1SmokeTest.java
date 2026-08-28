package smpp.companion.proxy.relay;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.util.AsciiString;
import io.netty.util.concurrent.DefaultThreadFactory;

import smpp.companion.proxy.observability.CapturingRelayObserver;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 2.2 Task 9 / AC6(a)+AC7 &mdash; the A-1 mechanics smoke on REAL SOCKETS (RELAY-011, the
 * load-bearing CI proof) plus the REL-1 transit roundtrip, both driven end-to-end through the REAL
 * acceptor ({@code RelayServerLifecycle.start()} &rarr; the production ingress/egress initializers
 * &rarr; {@code BindInterceptor} + the per-leg relay handlers) against the {@link MockSmsc} in-JVM mock on
 * the production codec. The legacy clients are plain blocking loopback sockets; every PDU is
 * hand-authored wire bytes (independent of the codec under test), with the REL-1 bind additionally
 * driven from the codec module's GOLDEN VECTOR corpus (byte-exact AD-14 through two real sockets +
 * the framer).
 *
 * <p><b>What each method proves:</b>
 * <ul>
 *   <li><b>RELAY-011 (AC6a, load-bearing):</b> two CONCURRENT {@code bind_transceiver} handshakes
 *       under the SAME {@code system_id} (both written before either response is read) both ROK;
 *       each bind couples to its OWN egress pair (two distinct mock sessions, each carrying the
 *       exact original bind bytes); a uniquely-tagged {@code deliver_sm} injected on each egress
 *       socket arrives on EXACTLY its originating legacy socket — zero DLR cross-bleed. The
 *       socket-level read IS the tag&rarr;channel assertion: the {@code RelayObserver} seam is
 *       deliberately channel-blind (AC5 — no content, no channel identity), so the legacy TCP
 *       connection is the channel identity, and the capturing observer pins the trigger counts
 *       (two {@code onBindAccept} under one identity, one {@code onFramedPdu} per relayed PDU).</li>
 *   <li><b>REL-1 roundtrip (AC7):</b> a {@code submit_sm} chain (legacy&rarr;SMSC) and a
 *       {@code deliver_sm} chain (SMSC&rarr;legacy) across a coupled pair — no drop, no duplicate,
 *       no corruption; PDU boundaries preserved (each chain written as ONE coalesced socket write,
 *       reassembled by the production framer on the receiving side into exactly as many complete
 *       framed PDUs).</li>
 *   <li><b>Real-socket teardown (the arms T8 could only simulate on {@code EmbeddedChannel}s):</b>
 *       a post-couple FIN (client {@code shutdownOutput()}) propagates teardown to BOTH legs + the
 *       registry and is OBSERVED; an RST ({@code SO_LINGER(0)} close) does the same. This is also
 *       the live proof of the AD-2 read-demand substrate: under {@code AUTO_READ=false} NO PDU
 *       would ever cross without the handlers' arming — every byte these tests observe flows
 *       through the write-completes-gates-read mechanism.</li>
 * </ul>
 *
 * <p><b>Oracle honesty (the story's load-bearing scoping):</b> the {@link MockSmsc} emulates the
 * carrier's affinity (it delivers on the socket it chooses) — this validates the RELAY's
 * pair-isolation mechanics, not the carrier's behavior. The independent CI oracle is T10's jSMPP
 * mock; the genuine A-1 falsification is the non-CI real-carrier plan
 * ({@code docs/a-1-carrier-test-plan.md}).
 */
@Tag("integration")
@Tag("relay")
@Tag("p1")
@Timeout(value = 60, threadMode = ThreadMode.SEPARATE_THREAD) // sockets + polls can hang — a stuck
// relay must FAIL a test, not hang the suite (the BindInterceptorTest pattern)
@SuppressWarnings("FutureReturnValueIgnored") // reason: Socket.shutdownOutput()/close() in tests are
// fire-and-forget probes — the assertions observe the RESULT (peer state, observer captures), never
// these calls' own returns.
class RelayA1SmokeTest {

    /** SMPP 3.4 §4.1.2 opaque PDUs the relay carries (never parsed — AD-3). */
    private static final int SUBMIT_SM = 0x00000004;
    private static final int DELIVER_SM = 0x00000105;

    /** The bind_resp wire contract, pinned as LITERALS (independent of the production constants). */
    private static final int BIND_TRANSCEIVER = 0x00000009;
    private static final int BIND_TRANSCEIVER_RESP = 0x80000009;

    /** The codec module's golden-vector corpus (sibling module; :proxy:test CWD = the proxy dir). */
    private static final Path GOLDEN_VECTORS = Path.of("../codec/src/test/resources/golden-vectors");

    private final List<Socket> clients = new ArrayList<>();
    private MockSmsc smsc;
    private RelayServerLifecycle relay;
    private RelayTestFixtures.ModeBRelayHarness harness;
    private int relayPort;

    @BeforeEach
    void startMockSmscAndRealRelay() {
        smsc = MockSmsc.start();
        relayPort = RelayTestFixtures.freePort();
        harness = RelayTestFixtures.modeBRelayHarness(
                RelayTestFixtures.modeBProperties(relayPort, 1, "127.0.0.1", smsc.port()));
        // The REAL production wiring behind the REAL acceptor — the T6-review deferred wiring pin:
        // real PDUs through the acceptor bite on any dropped wiring line.
        relay = new RelayServerLifecycle(
                harness.properties(), newGroup(), newOptions(), harness.ingressInitializer());
        relay.start();
        assertThat(relay.isRunning()).as("precondition: the relay acceptor is up").isTrue();
    }

    @AfterEach
    void stopEverything() {
        clients.forEach(socket -> {
            try {
                socket.close();
            } catch (IOException ignored) {
                // teardown best-effort — the relay's own teardown is what the tests assert
            }
        });
        clients.clear();
        if (relay != null) {
            relay.stop(); // idempotent; also quiesces the shared event loop
        }
        if (smsc != null) {
            smsc.close();
        }
    }

    // ---------- RELAY-011: the A-1 mechanics smoke (load-bearing) ----------

    @Test
    @DisplayName("RELAY-011: two CONCURRENT binds under one system_id both ROK, each couples to its own "
            + "egress pair, and a tagged deliver_sm per egress lands on EXACTLY its originating legacy "
            + "socket — zero DLR cross-bleed")
    void twoConcurrentBindsSameSystemIdZeroDlrCrossBleed() throws IOException {
        try (Socket clientA = connectLegacyClient(); Socket clientB = connectLegacyClient()) {
            byte[] bindA = bindRequest(1, "legacy1", "pw123456");
            byte[] bindB = bindRequest(2, "legacy1", "pw123456");
            // CONCURRENT handshakes: both binds are on the wire before either response is read.
            writePdu(clientA, bindA);
            writePdu(clientB, bindB);
            assertRokBindResp(readPdu(clientA), 1);
            assertRokBindResp(readPdu(clientB), 2);

            // Each bind coupled to its OWN egress pair: two distinct SMSC sessions, each carrying
            // the AD-14 byte-exact original bind. Match by content (session order is an accept race).
            MockSmsc.pollUntil(() -> smsc.sessions().size() >= 2);
            MockSmsc.Session smppSideA = sessionBoundWith(bindA);
            MockSmsc.Session smppSideB = sessionBoundWith(bindB);
            assertThat(smppSideA).as("two distinct egress pairs — one per ingress").isNotSameAs(smppSideB);
            assertThat(harness.registry().size())
                    .as("both coupled pairs are live (distinct ingress Channels, same system_id)").isEqualTo(2);

            // Uniquely-tagged deliver_sm injected per egress socket (the carrier-affinity emulation).
            byte[] deliverToA = opaquePdu(DELIVER_SM, 1001, "DLR-FOR-BIND-A");
            byte[] deliverToB = opaquePdu(DELIVER_SM, 1002, "DLR-FOR-BIND-B");
            smppSideA.deliver(deliverToA);
            smppSideB.deliver(deliverToB);

            assertThat(readPdu(clientA))
                    .as("the deliver_sm injected on pair A's SMSC socket reaches legacy client A, byte-exact")
                    .isEqualTo(deliverToA);
            assertThat(readPdu(clientB))
                    .as("the deliver_sm injected on pair B's SMSC socket reaches legacy client B, byte-exact")
                    .isEqualTo(deliverToB);
            // ZERO cross-bleed and no duplicates: nothing further arrives on either leg (and neither
            // leg was torn down by the misdelivery).
            assertNoFurtherPdu(clientA);
            assertNoFurtherPdu(clientB);

            // The pinned triggers: two ROK couples under the SAME identity (A-1's premise observed at
            // the relay), one onFramedPdu per relayed PDU — read on the EGRESS legs.
            assertThat(harness.observer().bindAccepts())
                    .as("onBindAccept fired exactly at each couple — twice, same system_id")
                    .containsExactly(
                            new SystemId(new AsciiString("legacy1")), new SystemId(new AsciiString("legacy1")));
            assertThat(harness.observer().framedPdus())
                    .as("one fire per relayed PDU, on the leg it was read from")
                    .containsExactly(Direction.EGRESS, Direction.EGRESS);
            assertThat(harness.observer().bindRejects()).isEmpty();
        }
    }

    // ---------- REL-1: the transit roundtrip (golden-vector-driven bind) ----------

    @Test
    @DisplayName("REL-1: submit_sm (legacy→SMSC) + deliver_sm (SMSC→legacy) roundtrip across a coupled "
            + "pair — no drop, no duplicate, no corruption, boundaries preserved; the golden-vector bind "
            + "crosses both real sockets byte-exact (AD-14)")
    void rel1RoundtripNoDropDupCorruptionBoundariesPreserved() throws IOException {
        byte[] goldenBind = goldenBindTransceiverRequest();
        try (Socket legacy = connectLegacyClient()) {
            writePdu(legacy, goldenBind);
            assertRokBindResp(readPdu(legacy), sequenceOf(goldenBind));

            MockSmsc.Session smppSide = smsc.awaitSession(0);
            assertThat(smppSide.bindFrame())
                    .as("AD-14: the golden-vector bind reaches the SMSC byte-exact through the framer, "
                            + "the interceptor, and two real sockets")
                    .isEqualTo(goldenBind);

            // submit_sm chain legacy→SMSC: FOUR distinct PDUs in ONE coalesced socket write — the
            // production framer on the mock side must yield exactly four complete framed PDUs.
            List<byte[]> submits = List.of(
                    opaquePdu(SUBMIT_SM, 201, "SUBMIT-ONE"),
                    opaquePdu(SUBMIT_SM, 202, "SUBMIT-TWO"),
                    opaquePdu(SUBMIT_SM, 203, "SUBMIT-THREE"),
                    opaquePdu(SUBMIT_SM, 204, "SUBMIT-FOUR"));
            writeRaw(legacy, concat(submits));
            assertThat(smppSide.awaitPdus(4))
                    .as("REL-1: no drop, no duplicate, no corruption, order preserved (one capture per "
                            + "framed PDU — boundaries preserved)")
                    .containsExactlyElementsOf(submits);

            // deliver_sm chain SMSC→legacy: THREE distinct PDUs in ONE mock-side write — the legacy
            // client reads exactly three complete framed PDUs, byte-exact.
            List<byte[]> delivers = List.of(
                    opaquePdu(DELIVER_SM, 301, "DLR-ONE"),
                    opaquePdu(DELIVER_SM, 302, "DLR-TWO"),
                    opaquePdu(DELIVER_SM, 303, "DLR-THREE"));
            smppSide.deliverAll(concat(delivers));
            assertThat(readPdu(legacy)).isEqualTo(delivers.get(0));
            assertThat(readPdu(legacy)).isEqualTo(delivers.get(1));
            assertThat(readPdu(legacy)).isEqualTo(delivers.get(2));
            assertNoFurtherPdu(legacy);

            assertThat(harness.registry().size())
                    .as("the pair stays coupled — the roundtrip never tore it down").isEqualTo(1);
            assertThat(harness.observer().framedPdus())
                    .as("one fire per relayed PDU on the leg it was read from: 4 submits (INGRESS leg) "
                            + "then 3 delivers (EGRESS leg)")
                    .containsExactly(
                            Direction.INGRESS, Direction.INGRESS, Direction.INGRESS, Direction.INGRESS,
                            Direction.EGRESS, Direction.EGRESS, Direction.EGRESS);
        }
    }

    // ---------- the real-socket teardown arms (T8's deferred live proofs) ----------

    @Test
    @DisplayName("real-socket teardown: a post-couple FIN propagates to BOTH legs + the registry and is "
            + "OBSERVED (RELAY-008); an RST (SO_LINGER 0) tears both legs down, observed (RELAY-010)")
    void realSocketHalfCloseAndRstTearDownBothLegsAndAreObserved() throws IOException {
        // (a) FIN — the client half-closes (shutdownOutput): the pair tears down, observed on both legs.
        try (Socket legacy = connectLegacyClient()) {
            writePdu(legacy, bindRequest(7, "legacy1", "pw123456"));
            assertRokBindResp(readPdu(legacy), 7);
            MockSmsc.Session smppSide = smsc.awaitSession(0);

            legacy.shutdownOutput(); // FIN — read side stays open (a true half-close)

            MockSmsc.pollUntil(smppSide::closed);
            MockSmsc.pollUntil(() -> harness.registry().size() == 0);
            MockSmsc.pollUntil(() -> harness.observer().connectionCloses().size() >= 2);
            assertThat(harness.observer().connectionCloses())
                    .as("RELAY-008 on real sockets: the FIN tears BOTH legs down and the teardown is "
                            + "OBSERVED (never a silent drop)")
                    .extracting(CapturingRelayObserver.ConnectionClose::direction)
                    .containsExactlyInAnyOrder(Direction.INGRESS, Direction.EGRESS);
            assertThat(harness.observer().connectionCloses())
                    .as("the coupled pair's unstashed/propagated close reason is PEER_HALF_CLOSE")
                    .extracting(CapturingRelayObserver.ConnectionClose::reason)
                    .containsOnly(CloseReason.PEER_HALF_CLOSE);
        }

        // (b) RST — SO_LINGER(0) close sends a reset: both legs down, teardown observed again.
        Socket rst = connectLegacyClient();
        writePdu(rst, bindRequest(8, "legacy1", "pw123456"));
        assertRokBindResp(readPdu(rst), 8);
        MockSmsc.Session smppSide2 = smsc.awaitSession(1);
        try {
            rst.setSoLinger(true, 0);
        } catch (IOException e) {
            throw new IllegalStateException("SO_LINGER unavailable — cannot inject the RST", e);
        }
        rst.close(); // RST on loopback

        MockSmsc.pollUntil(smppSide2::closed);
        MockSmsc.pollUntil(() -> harness.registry().size() == 0);
        MockSmsc.pollUntil(() -> harness.observer().connectionCloses().size() >= 4);
        assertThat(harness.observer().connectionCloses())
                .as("RELAY-010 on real sockets: the RST tears BOTH legs down, observed — 4 total close "
                        + "events across the two scenarios, both directions twice")
                .extracting(CapturingRelayObserver.ConnectionClose::direction)
                .containsExactlyInAnyOrder(Direction.INGRESS, Direction.EGRESS, Direction.INGRESS, Direction.EGRESS);
        assertThat(harness.observer().connectionCloses())
                .extracting(CapturingRelayObserver.ConnectionClose::reason)
                .as("an RST surfaces as PEER_RST (read-armed reset) or PEER_HALF_CLOSE (bare inactive) — "
                        + "both are the observed, fail-closed teardown")
                .isSubsetOf(CloseReason.PEER_RST, CloseReason.PEER_HALF_CLOSE, CloseReason.OTHER);
    }

    // ---------- fixtures ----------

    private Socket connectLegacyClient() throws IOException {
        Socket socket = new Socket(InetAddress.getLoopbackAddress(), relayPort);
        socket.setSoTimeout(4_000);
        clients.add(socket); // @AfterEach closes whatever the test itself did not
        return socket;
    }

    /** Mirrors the RelayNettyConfig bean: the Netty 4.2 NIO idiom, named platform threads (AD-1). */
    private static EventLoopGroup newGroup() {
        return new MultiThreadIoEventLoopGroup(
                1, new DefaultThreadFactory("relay-a1-smoke"), NioIoHandler.newFactory());
    }

    private RelayChannelOptions newOptions() {
        return new RelayChannelOptions(harness.properties(), PooledByteBufAllocator.DEFAULT);
    }

    /** The mock session whose captured bind frame is byte-identical to the given bind (pair identity). */
    private MockSmsc.Session sessionBoundWith(byte[] bind) {
        return smsc.sessions().stream()
                .filter(s -> Arrays.equals(s.bindFrame(), bind))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no SMSC session captured the given bind bytes"));
    }

    /**
     * The golden-vector {@code bind_transceiver} request (all fields populated): loaded from the codec
     * module's corpus, parsed from the single-line provenance header's {@code raw-hex:} token —
     * hand-authored-from-the-spec bytes, produced independently of the codec under test.
     */
    private static byte[] goldenBindTransceiverRequest() throws IOException {
        assertThat(GOLDEN_VECTORS)
                .as("the golden-vector corpus must exist (repo layout: codec is the sibling module)")
                .isDirectory();
        Path vector = GOLDEN_VECTORS.resolve("bind_transceiver_request_all_fields.smpp");
        assertThat(vector).as("the REL-1 golden bind vector must exist").isRegularFile();
        String firstLine = Files.readAllLines(vector, StandardCharsets.UTF_8).get(0);
        Matcher matcher = Pattern.compile("raw-hex: ([0-9a-f]+)").matcher(firstLine);
        assertThat(matcher.find())
                .as("the golden vector carries its raw-hex token (GoldenVectorCorpusTest format)")
                .isTrue();
        return java.util.HexFormat.of().parseHex(matcher.group(1));
    }

    // ---------- hand-authored PDU builders (raw bytes — independent of the codec) ----------

    private static byte[] bindRequest(int sequence, String systemId, String password) {
        byte[] id = ascii(systemId);
        byte[] pw = ascii(password);
        byte[] type = ascii("SMPP");
        byte[] range = ascii("");
        int body = (id.length + 1) + (pw.length + 1) + (type.length + 1) + 3 + (range.length + 1);
        return assemble(BIND_TRANSCEIVER, 0, sequence, body, out -> {
            out.put(id).put((byte) 0);
            out.put(pw).put((byte) 0);
            out.put(type).put((byte) 0);
            out.put((byte) 0x34).put((byte) 0).put((byte) 0);
            out.put(range).put((byte) 0);
        });
    }

    /** An OPAQUE non-bind PDU carrying an ASCII tag body (never parsed — AD-3; the tag is the probe). */
    private static byte[] opaquePdu(int commandId, int sequence, String tag) {
        byte[] body = ascii(tag);
        return assemble(commandId, 0, sequence, body.length, out -> out.put(body));
    }

    private interface BodyWriter {
        void writeTo(ByteBuffer out);
    }

    private static byte[] assemble(int commandId, int commandStatus, int sequence, int bodyLen, BodyWriter writer) {
        ByteBuffer out = ByteBuffer.allocate(16 + bodyLen);
        out.putInt(16 + bodyLen).putInt(commandId).putInt(commandStatus).putInt(sequence);
        writer.writeTo(out);
        return out.array();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(List<byte[]> pdus) {
        int total = pdus.stream().mapToInt(p -> p.length).sum();
        ByteBuffer out = ByteBuffer.allocate(total);
        pdus.forEach(out::put);
        return out.array();
    }

    // ---------- raw-socket PDU I/O ----------

    private static void writePdu(Socket socket, byte[] pdu) throws IOException {
        socket.getOutputStream().write(pdu);
        socket.getOutputStream().flush();
    }

    private static void writeRaw(Socket socket, byte[] bytes) throws IOException {
        socket.getOutputStream().write(bytes);
        socket.getOutputStream().flush();
    }

    /** Reads exactly ONE framed PDU (16-octet header, then {@code command_length - 16} body octets). */
    private static byte[] readPdu(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] header = in.readNBytes(16);
        if (header.length < 16) {
            throw new EOFException("peer closed mid-header (expected a complete framed PDU)");
        }
        int commandLength = ByteBuffer.wrap(header).getInt(0);
        if (commandLength < 16) {
            throw new IOException("nonsense command_length " + commandLength + " on the wire");
        }
        byte[] pdu = Arrays.copyOf(header, commandLength);
        int body = in.readNBytes(pdu, 16, commandLength - 16);
        if (body < commandLength - 16) {
            throw new EOFException("peer closed mid-body (partial frame reached the wire!)");
        }
        return pdu;
    }

    /** The pinned ROK bind_resp contract, asserted on LITERALS (independent of the production constants). */
    private static void assertRokBindResp(byte[] resp, int expectedSequence) {
        ByteBuffer header = ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the resp's command_length covers the whole PDU").isEqualTo(resp.length);
        assertThat(commandId).as("bind_transceiver answered by bind_transceiver_resp").isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(commandStatus).as("ESME_ROK — the bind coupled (A-1's premise at this leg)").isZero();
        assertThat(sequence).as("the resp answers the request's sequence_number").isEqualTo(expectedSequence);
    }

    /** Fails iff anything else arrives (cross-bleed/duplicate) or the peer already closed the leg. */
    private static void assertNoFurtherPdu(Socket socket) throws IOException {
        int original = socket.getSoTimeout();
        socket.setSoTimeout(300);
        try {
            int first = socket.getInputStream().read();
            if (first < 0) {
                throw new AssertionError("the relay closed the leg — expected a live coupled pair");
            }
            throw new AssertionError("an extra byte arrived — a duplicate or cross-bled PDU (first byte "
                    + first + ")");
        } catch (SocketTimeoutException clean) {
            // nothing further arrived — the pass condition
        } finally {
            socket.setSoTimeout(original);
        }
    }

    private static int sequenceOf(byte[] pdu) {
        return ByteBuffer.wrap(pdu).getInt(12);
    }
}
