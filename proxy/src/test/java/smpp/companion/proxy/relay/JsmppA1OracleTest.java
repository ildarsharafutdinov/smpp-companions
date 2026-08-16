package smpp.companion.proxy.relay;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

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

import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 2.2 Task 10 / AC6(b) — <b>OBS-038, the independent A-1 conformance oracle</b> (the
 * load-bearing second half of AC6): the SAME affinity scenario as RELAY-011, but with the SMSC
 * side played by the {@link JsmppSmscServer} (jSMPP 3.0.2) instead of the production-codec
 * {@link MockSmsc}. jSMPP is a full second SMPP stack — it PARSES everything the relay splices
 * onto the egress sockets and CONSTRUCTS everything the legacy clients read back — so this test
 * shares NEITHER the production codec's bugs NOR its A-1 assumption: a mis-framed bind/submit,
 * a corrupted splice, or a cross-coupled pair makes the independent stack reject or garble the
 * exchange and the test go RED.
 *
 * <p><b>The scenario (test-coverage-scenarios.md :1267–1271):</b> two CONCURRENT
 * {@code bind_transceiver} handshakes under ONE {@code system_id} through the REAL relay
 * ({@code RelayServerLifecycle} acceptor + the production initializers) to the jSMPP oracle —
 * both {@code bind_*_resp} ROK (the oracle accepted two same-{@code system_id} binds, one per
 * connection); then a {@code submit_sm} on bind A yields {@code submit_sm_resp} + the DLR
 * {@code deliver_sm} on <b>bind A's channel ONLY — never bind B</b> (and symmetrically for B):
 * the socket-level read IS the tag&rarr;channel assertion (the {@code SpliceObserver} seam is
 * deliberately channel-blind, AC5 — the legacy TCP connection is the channel identity; the
 * capturing observer pins the trigger counts).
 *
 * <p><b>Oracle honesty:</b> this is the strongest CI approximation of A-1 — mechanics + an
 * independent stack — not the genuine falsification; that remains the non-CI real-carrier plan
 * ({@code docs/a-1-carrier-test-plan.md}, OBS-035/036/037).
 */
@Tag("integration")
@Tag("relay")
@Tag("p1")
@Timeout(value = 60, threadMode = ThreadMode.SEPARATE_THREAD) // sockets + polls can hang — a stuck
// relay must FAIL a test, not hang the suite (the RelayA1SmokeTest pattern)
class JsmppA1OracleTest {

    /**
     * SMPP 3.4 §5.1.2.1 command ids, pinned as LITERALS (independent of the production constants).
     * NOTE {@code deliver_sm = 0x00000005} — the spec's actual id (§5.1.2.1, verified against the
     * repo PDF); the first draft pinned {@code 0x00000105}, a NON-EXISTENT id that the opaque-splice
     * T9 mock never caught (any non-bind id works as an opaque tag carrier) but jSMPP's CONSTRUCTED
     * deliver_sm exposed immediately — another independent-oracle bite.
     */
    private static final int SUBMIT_SM = 0x00000004;
    private static final int SUBMIT_SM_RESP = 0x80000004;
    private static final int DELIVER_SM = 0x00000005;
    private static final int DELIVER_SM_RESP = 0x80000005;
    private static final int BIND_TRANSCEIVER = 0x00000009;
    private static final int BIND_TRANSCEIVER_RESP = 0x80000009;

    /** One {@code system_id} shared by both binds — A-1's premise. */
    private static final String SYSTEM_ID = "legacy1";
    private static final String PASSWORD = "pw123456";

    private final List<Socket> clients = new ArrayList<>();
    private JsmppSmscServer smsc;
    private RelayServerLifecycle relay;
    private RelayTestFixtures.ModeBRelayHarness harness;
    private int relayPort;

    @BeforeEach
    void startJsmppOracleAndRealRelay() {
        smsc = JsmppSmscServer.start();
        relayPort = RelayTestFixtures.freePort();
        harness = RelayTestFixtures.modeBRelayHarness(
                RelayTestFixtures.modeBProperties(relayPort, 1, "127.0.0.1", smsc.port()));
        // The REAL production wiring behind the REAL acceptor (the T6-review deferred wiring pin):
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

    // ---------- OBS-038: the independent A-1 affinity oracle (load-bearing) ----------

    @Test
    @DisplayName("OBS-038: two CONCURRENT binds under one system_id through the relay both ROK at the "
            + "jSMPP oracle; a submit_sm on bind A yields submit_sm_resp + the DLR deliver_sm on bind "
            + "A's channel ONLY — never bind B (and symmetrically for B)")
    void twoConcurrentBindsSameSystemIdDlrRidesItsOwnPair() throws IOException {
        try (Socket clientA = connectLegacyClient(); Socket clientB = connectLegacyClient()) {
            byte[] bindA = bindRequest(1, SYSTEM_ID, PASSWORD);
            byte[] bindB = bindRequest(2, SYSTEM_ID, PASSWORD);
            // CONCURRENT handshakes: both binds are on the wire before either response is read —
            // and both were PARSED + ROK'd by jSMPP (the independent stack), not just echoed.
            writePdu(clientA, bindA);
            writePdu(clientB, bindB);
            assertRokBindResp(readPdu(clientA), 1);
            assertRokBindResp(readPdu(clientB), 2);

            // The oracle's own view of A-1's premise: TWO sessions bound under the ONE system_id.
            List<JsmppSmscServer.BoundSession> bound = smsc.awaitSessions(2);
            assertThat(bound)
                    .as("the jSMPP oracle accepted two binds under one system_id")
                    .extracting(JsmppSmscServer.BoundSession::systemId)
                    .containsExactlyInAnyOrder(SYSTEM_ID, SYSTEM_ID);
            assertThat(harness.registry().size())
                    .as("both coupled pairs are live (distinct ingress Channels, same system_id)")
                    .isEqualTo(2);

            // --- bind A's leg: submit_sm → submit_sm_resp + DLR deliver_sm, both back on A only ---
            writePdu(clientA, submitSm(501, "SUBMIT-FROM-A"));
            // jSMPP sends the submit_sm_resp when the callback returns and the DLR from the worker —
            // the two are serialized on the session output but their ORDER is a fixture-internal
            // race, so both are read and classified.
            List<byte[]> aAnswers = List.of(readPdu(clientA), readPdu(clientA));
            byte[] submitRespA = selectByCommandId(aAnswers, SUBMIT_SM_RESP);
            byte[] dlrA = selectByCommandId(aAnswers, DELIVER_SM);
            assertSubmitSmResp(submitRespA, 501);
            assertDeliverSmTag(dlrA, "DLR:SUBMIT-FROM-A");
            answerDeliverSmResp(clientA, dlrA); // the well-behaved receipt: resp rides the pair back
            assertNoFurtherPdu(clientB); // B saw NEITHER A's resp NOR A's DLR — zero cross-bleed

            // --- the symmetric leg ---
            writePdu(clientB, submitSm(502, "SUBMIT-FROM-B"));
            List<byte[]> bAnswers = List.of(readPdu(clientB), readPdu(clientB));
            byte[] submitRespB = selectByCommandId(bAnswers, SUBMIT_SM_RESP);
            byte[] dlrB = selectByCommandId(bAnswers, DELIVER_SM);
            assertSubmitSmResp(submitRespB, 502);
            assertDeliverSmTag(dlrB, "DLR:SUBMIT-FROM-B");
            answerDeliverSmResp(clientB, dlrB);
            assertNoFurtherPdu(clientA); // A saw nothing of B's exchange either

            // The oracle's affinity bookkeeping: two submits, each DLR'd on ITS OWN session — the
            // affinity decision was jSMPP's; the relay only had to preserve it per pair.
            List<JsmppSmscServer.SubmittedSm> submitted = smsc.awaitSubmits(2);
            assertThat(submitted)
                    .as("each bind's submit arrived on its own egress (ordered: A's leg completed "
                            + "before B's submit was written)")
                    .extracting(submit -> new String(submit.shortMessage(), StandardCharsets.US_ASCII))
                    .containsExactly("SUBMIT-FROM-A", "SUBMIT-FROM-B");
            assertThat(submitted.get(0).session())
                    .as("the two submits rode two DISTINCT jSMPP sessions (one per bind)")
                    .isNotSameAs(submitted.get(1).session());
            assertThat(smsc.anomalies())
                    .as("a healthy oracle run accumulates no SMSC-side failure — an entry here "
                            + "would mean a pass was explained away, not proven")
                    .isEmpty();
            assertThat(harness.registry().size())
                    .as("both pairs stayed coupled through the full exchange")
                    .isEqualTo(2);

            // The pinned triggers: two ROK flips under the SAME identity (A-1's premise observed
            // at the relay) and one onFramedPdu per spliced PDU — 2 submits + 2 deliver_sm_resps
            // read on the INGRESS legs, 2 submit_sm_resps + 2 DLRs read on the EGRESS legs (the
            // exact resp/DLR interleaving per pair is a fixture-internal wire race — counts, not
            // order).
            assertThat(harness.observer().bindAccepts())
                    .as("onBindAccept fired exactly at each flip — twice, same system_id")
                    .containsExactly(
                            new SystemId(new AsciiString(SYSTEM_ID)), new SystemId(new AsciiString(SYSTEM_ID)));
            List<Direction> framed = harness.observer().framedPdus();
            assertThat(framed).as("2 submits + 2 dlr resps (ingress) + 2 resps + 2 DLRs (egress)").hasSize(8);
            assertThat(framed.stream().filter(Direction.INGRESS::equals).toList())
                    .as("one fire per PDU read on an ingress leg")
                    .hasSize(4);
            assertThat(framed.stream().filter(Direction.EGRESS::equals).toList())
                    .as("one fire per PDU read on an egress leg")
                    .hasSize(4);
            assertThat(harness.observer().bindRejects()).isEmpty();
        }
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
                1, new DefaultThreadFactory("jsmpp-a1-oracle"), NioIoHandler.newFactory());
    }

    private RelayChannelOptions newOptions() {
        return new RelayChannelOptions(harness.properties(), PooledByteBufAllocator.DEFAULT);
    }

    // ---------- hand-authored PDU builders (raw bytes — independent of the codec) ----------

    private static byte[] bindRequest(int sequence, String systemId, String password) {
        byte[] id = ascii(systemId);
        byte[] pw = ascii(password);
        byte[] type = ascii("SMPP");
        int body = (id.length + 1) + (pw.length + 1) + (type.length + 1) + 3 + 1;
        return assemble(BIND_TRANSCEIVER, 0, sequence, body, out -> {
            out.put(id).put((byte) 0);
            out.put(pw).put((byte) 0);
            out.put(type).put((byte) 0);
            out.put((byte) 0x34).put((byte) 0).put((byte) 0); // interface_version 0x34, ton, npi
            out.put((byte) 0); // address_range: empty C-octet
        });
    }

    /**
     * A WELL-FORMED {@code submit_sm} whose {@code short_message} carries the ASCII tag probe —
     * unlike the MockSmsc (opaque capture), the jSMPP oracle PARSES this PDU, so EVERY §4.4.1 field
     * must be present and every C-octet NUL-terminated: {@code service_type}, the two addr triples,
     * {@code esm_class}/{@code protocol_id}/{@code priority_flag}, the two EMPTY C-octets
     * {@code schedule_delivery_time} + {@code validity_period}, then
     * {@code registered_delivery}/{@code replace_if_present_flag}/{@code data_coding}/
     * {@code sm_default_msg_id}, {@code sm_length}, {@code short_message}. (The first draft omitted
     * the two C-octets + {@code replace_if_present_flag} and double-counted {@code sm_length} —
     * jSMPP's strict decomposer threw {@code ArrayIndexOutOfBoundsException} past the declared
     * {@code command_length} and answered NOTHING: precisely the independent-parser bite AC6(b)
     * exists for; the MockSmsc never saw it because it splices submits opaquely.)
     */
    private static byte[] submitSm(int sequence, String tag) {
        byte[] source = ascii("1111");
        byte[] dest = ascii("9999");
        byte[] message = ascii(tag);
        int body = 1 // service_type: empty C-octet
                + 1 + 1 + (source.length + 1) // source_addr_ton/npi + source_addr
                + 1 + 1 + (dest.length + 1) // dest_addr_ton/npi + destination_addr
                + 3 // esm_class, protocol_id, priority_flag
                + 1 + 1 // schedule_delivery_time + validity_period: empty C-octets
                + 4 // registered_delivery, replace_if_present_flag, data_coding, sm_default_msg_id
                + 1 // sm_length
                + message.length;
        return assemble(SUBMIT_SM, 0, sequence, body, out -> {
            out.put((byte) 0); // service_type: empty C-octet
            out.put((byte) 2).put((byte) 1); // source_addr_ton/npi
            out.put(source).put((byte) 0); // source_addr C-octet
            out.put((byte) 2).put((byte) 1); // dest_addr_ton/npi
            out.put(dest).put((byte) 0); // destination_addr C-octet
            out.put((byte) 0); // esm_class
            out.put((byte) 0); // protocol_id
            out.put((byte) 0); // priority_flag
            out.put((byte) 0); // schedule_delivery_time: empty C-octet
            out.put((byte) 0); // validity_period: empty C-octet
            out.put((byte) 0); // registered_delivery
            out.put((byte) 0); // replace_if_present_flag (§5.2.17: reserved, NULL)
            out.put((byte) 0); // data_coding
            out.put((byte) 0); // sm_default_msg_id
            out.put((byte) message.length); // sm_length
            out.put(message); // short_message: the tag probe
        });
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

    // ---------- raw-socket PDU I/O ----------

    private static void writePdu(Socket socket, byte[] pdu) throws IOException {
        socket.getOutputStream().write(pdu);
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
        byte[] pdu = java.util.Arrays.copyOf(header, commandLength);
        int body = in.readNBytes(pdu, 16, commandLength - 16);
        if (body < commandLength - 16) {
            throw new EOFException("peer closed mid-body (partial frame reached the wire!)");
        }
        return pdu;
    }

    /** The PDU's {@code command_id} header octets 4–7. */
    private static int commandIdOf(byte[] pdu) {
        return ByteBuffer.wrap(pdu).getInt(4);
    }

    /** Exactly one of the read PDUs must carry the given command_id — returns it. */
    private static byte[] selectByCommandId(List<byte[]> pdus, int commandId) {
        List<byte[]> matches = pdus.stream().filter(pdu -> commandIdOf(pdu) == commandId).toList();
        assertThat(matches)
                .as("exactly one PDU with command_id 0x%08X among %s"
                        .formatted(commandId, pdus.stream().map(p -> "0x%08X".formatted(commandIdOf(p))).toList()))
                .hasSize(1);
        return matches.get(0);
    }

    // ---------- wire-contract assertions (LITERALS — independent of the production constants) ----------

    /** The pinned ROK bind_resp contract. */
    private static void assertRokBindResp(byte[] resp, int expectedSequence) {
        ByteBuffer header = ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the resp's command_length covers the whole PDU").isEqualTo(resp.length);
        assertThat(commandId).as("bind_transceiver answered by bind_transceiver_resp").isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(commandStatus).as("ESME_ROK — the jSMPP oracle accepted the bind (A-1's premise)").isZero();
        assertThat(sequence).as("the resp answers the request's sequence_number").isEqualTo(expectedSequence);
    }

    /** The submit_sm_resp contract: ROK, answering the submit's sequence (the oracle parsed it). */
    private static void assertSubmitSmResp(byte[] resp, int expectedSequence) {
        ByteBuffer header = ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the resp's command_length covers the whole PDU").isEqualTo(resp.length);
        assertThat(commandId).as("submit_sm answered by submit_sm_resp").isEqualTo(SUBMIT_SM_RESP);
        assertThat(commandStatus).as("ESME_ROK — jSMPP parsed + accepted the spliced submit_sm").isZero();
        assertThat(sequence)
                .as("sequence integrity through the relay: the resp answers THIS submit's sequence")
                .isEqualTo(expectedSequence);
    }

    /** The DLR contract: a deliver_sm (constructed by jSMPP) whose body carries the unique tag. */
    private static void assertDeliverSmTag(byte[] pdu, String expectedTag) {
        ByteBuffer header = ByteBuffer.wrap(pdu);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        assertThat(commandLength).as("the deliver_sm's command_length covers the whole PDU").isEqualTo(pdu.length);
        assertThat(commandId).as("the DLR is a deliver_sm").isEqualTo(DELIVER_SM);
        assertThat(commandStatus).as("a deliver_sm REQUEST carries command_status 0").isZero();
        assertThat(new String(pdu, 16, pdu.length - 16, StandardCharsets.US_ASCII))
                .as("the DLR body carries the unique tag of the submit that triggered it")
                .contains(expectedTag);
    }

    /** Answers the DLR on the same leg (echoing its sequence) — the well-behaved receipt roundtrip. */
    private static void answerDeliverSmResp(Socket socket, byte[] deliverSm) throws IOException {
        int sequence = ByteBuffer.wrap(deliverSm).getInt(12);
        ByteBuffer resp = ByteBuffer.allocate(16);
        resp.putInt(16).putInt(DELIVER_SM_RESP).putInt(0).putInt(sequence);
        writePdu(socket, resp.array());
    }

    /** Fails iff anything else arrives (cross-bleed/duplicate) or the peer already closed the leg. */
    private static void assertNoFurtherPdu(Socket socket) throws IOException {
        int original = socket.getSoTimeout();
        socket.setSoTimeout(300);
        try {
            int first = socket.getInputStream().read();
            if (first < 0) {
                throw new AssertionError("the relay closed the leg — expected a live spliced pair");
            }
            throw new AssertionError("an extra byte arrived — a duplicate or cross-bled PDU (first byte "
                    + first + ")");
        } catch (SocketTimeoutException clean) {
            // nothing further arrived — the pass condition
        } finally {
            socket.setSoTimeout(original);
        }
    }
}
