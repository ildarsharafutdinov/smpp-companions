package smpp.companion.proxy.relay;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executor;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;
import org.junit.jupiter.api.io.TempDir;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.util.concurrent.DefaultThreadFactory;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Story 3.3 T7 — the loopback integration suite for the ratified <b>[B]</b> topology on REAL SOCKETS:
 * TWO relay instances in one JVM (the forward with its plaintext trusted-leg listener + per-session
 * TLS dials; the reverse with its internet-leg TLS listener + plaintext SMSC dial) against the
 * in-JVM {@link MockSmsc}. The legacy clients are plain blocking sockets; every PDU is hand-authored
 * wire bytes (independent of the codec under test).
 *
 * <p><b>What each method proves (the story's AC matrix):</b>
 * <ul>
 *   <li><b>Mode A e2e (AC1 shape):</b> a bind for a ROUTED {@code system_id} traverses trusted leg →
 *       one-way TLS dial → the reverse's plaintext SMSC dial, ROK end-to-end, the mock captures the
 *       AD-14 byte-exact original bind, and a {@code deliver_sm} rides the same coupled pair back.</li>
 *   <li><b>Mode C mTLS e2e (AC1):</b> the same chain with the per-instance client cert presented and
 *       REQUIRE'd.</li>
 *   <li><b>REQUIRE-negative (AC3):</b> a TLS peer WITHOUT a client cert fails the handshake at the
 *       reverse's listener — connection closed, no SMPP PDU emitted (the mock never sees a session).</li>
 *   <li><b>Routing miss (AC2):</b> an unrouted {@code system_id} gets the on-wire AD-33 collapse
 *       (header-only {@code ESME_RBINDFAIL} + close) and NOTHING reaches the reverse.</li>
 *   <li><b>N sessions per system_id:</b> two concurrent binds under ONE routed id each couple to
 *       their OWN forward→reverse→SMSC chain — the pairing is per channel, never per system_id.</li>
 *   <li><b>Cap (F13):</b> at {@code memory.concurrent-pairs} the acceptor refuses further connections
 *       (close, no response).</li>
 *   <li><b>Mode B regression:</b> the plaintext direct-leg cell stays byte-compatible with Story 2.2
 *       (the deep A-1/REL-1 coverage remains {@code RelayA1SmokeTest}; this is the suite-local pin
 *       that the [B] sweep changed nothing on that cell).</li>
 * </ul>
 *
 * <p><b>Oracle honesty:</b> the verifier on both instances is the AlwaysAllow stand-in — this suite
 * pins the TLS/routing/cap PLUMBING; the ROPC adjudication behind the same interceptor arms is
 * Story 3.2's suite. The reverse's SMSC leg is PLAINTEXT here by design (AD-12 amended).
 */
@Tag("integration")
@Tag("relay")
@Tag("sec")
@Tag("p1")
@Timeout(value = 90, threadMode = ThreadMode.SEPARATE_THREAD)
@SuppressWarnings("FutureReturnValueIgnored") // reason: Socket close/shutdown probes in tests are
// fire-and-forget — the assertions observe the RESULT (peer state, mock captures), never the calls.
class TlsModesLoopbackE2eTest {

    /** SMPP 3.4 §4.1.2 opaque PDU the splice carries (never parsed — AD-3). */
    private static final int DELIVER_SM = 0x00000105;

    /** The bind wire contract, pinned as LITERALS (independent of the production constants). */
    private static final int BIND_TRANSCEIVER = 0x00000009;
    private static final int BIND_TRANSCEIVER_RESP = 0x80000009;
    private static final int ESME_RBINDFAIL = 0x0000000D;

    private final List<Socket> clients = new ArrayList<>();
    private final List<EventLoopGroup> groups = new ArrayList<>();
    private final List<RelayServerLifecycle> lifecycles = new ArrayList<>();
    private MockSmsc smsc;
    private Path dir;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        dir = tempDir;
        smsc = MockSmsc.start();
    }

    @AfterEach
    void stopEverything() {
        clients.forEach(socket -> {
            try {
                socket.close();
            } catch (IOException ignored) {
                // teardown best-effort — the relays' own teardown is what the tests assert
            }
        });
        clients.clear();
        lifecycles.forEach(RelayServerLifecycle::stop);
        lifecycles.clear();
        groups.forEach(group -> group.shutdownGracefully());
        groups.clear();
        if (smsc != null) {
            smsc.close();
        }
    }

    // ---------------------------------------------------------------- Mode A e2e (AC1 shape)

    @Test
    @DisplayName("Mode A e2e: routed bind crosses trusted leg -> one-way TLS dial -> reverse -> SMSC; "
            + "ROK end-to-end; AD-14 byte-exact; deliver_sm rides the same pair")
    void modeAEndToEnd() throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        int reversePort = startReverse(RelayTestFixtures.reverseAProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", smsc.port()));
        int forwardPort = startForward(RelayTestFixtures.forwardAProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", reversePort));

        try (Socket legacy = connectLegacyClient(forwardPort)) {
            byte[] bind = bindRequest(1, "carrierOne", "pw123456");
            writePdu(legacy, bind);
            assertRokBindResp(readPdu(legacy), 1);

            MockSmsc.Session smppSide = smsc.awaitSession(0);
            assertThat(smppSide.bindFrame())
                    .as("AD-14: the ORIGINAL bind bytes cross TWO proxies + one TLS leg verbatim")
                    .isEqualTo(bind);

            byte[] deliver = opaquePdu(DELIVER_SM, 501, "DLR-MODE-A");
            smppSide.deliver(deliver);
            assertThat(readPdu(legacy))
                    .as("the deliver_sm rides the SAME coupled pair back to the legacy client")
                    .isEqualTo(deliver);
            assertNoFurtherPdu(legacy);
        }
    }

    // ---------------------------------------------------------------- Mode C mTLS e2e + REQUIRE-negative

    @Test
    @DisplayName("Mode C e2e: mTLS dial presents the per-instance cert, the reverse REQUIREs it — "
            + "ROK end-to-end, byte-exact, deliver_sm back")
    void modeCEndToEnd() throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        int reversePort = startReverse(RelayTestFixtures.reverseCProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", smsc.port()));
        int forwardPort = startForward(RelayTestFixtures.forwardCProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", reversePort));

        try (Socket legacy = connectLegacyClient(forwardPort)) {
            byte[] bind = bindRequest(2, "carrierOne", "pw123456");
            writePdu(legacy, bind);
            assertRokBindResp(readPdu(legacy), 2);

            MockSmsc.Session smppSide = smsc.awaitSession(0);
            assertThat(smppSide.bindFrame()).isEqualTo(bind);

            byte[] deliver = opaquePdu(DELIVER_SM, 502, "DLR-MODE-C");
            smppSide.deliver(deliver);
            assertThat(readPdu(legacy)).isEqualTo(deliver);
        }
    }

    @Test
    @DisplayName("Mode C REQUIRE-negative: a TLS peer WITHOUT a client cert fails the handshake at the "
            + "reverse listener — no SMPP byte is read, no SMSC session ever opens")
    void modeCRequireRefusesTheCertlessPeer() throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        int reversePort = startReverse(RelayTestFixtures.reverseCProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", smsc.port()));

        // A JDK TLS client that TRUSTS the reverse's server cert (so server auth succeeds and the
        // handshake reaches the client-cert request) but presents NO cert of its own.
        SSLSocket certless = trustOnlySslSocket(legs, reversePort);
        clients.add(certless);
        // TLS 1.3 timing note (empirically pinned): startHandshake() RETURNS normally for the
        // cert-less client — the server's (certificate_required) rejection lands one flight later
        // and surfaces on the FIRST I/O, which is exactly where the fail-closed posture shows.
        certless.startHandshake();
        assertThatThrownBy(() -> certless.getInputStream().read())
                .as("REQUIRE never WANT (AD-11/AD-13): the cert-less peer is refused — the alert or "
                        + "the close surfaces on the first read")
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("certificate_required");
        assertThat(smsc.sessions())
                .as("no SMPP PDU was ever read — the failure is BELOW the codec (AC3)")
                .isEmpty();
    }

    @Test
    @DisplayName("Mode C REQUIRE-negative (AC4, unanchored arm): a peer presenting a cert chained to a "
            + "FOREIGN CA fails the handshake — no SMPP byte, no SMSC session")
    void modeCRequireRefusesTheUnanchoredPeer() throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        int reversePort = startReverse(RelayTestFixtures.reverseCProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", smsc.port()));

        // A JDK TLS client that TRUSTS the reverse's server cert (server auth succeeds) and PRESENTS
        // the foreign-CA-chained client pair — a presented-but-UNANCHORED identity: AC4's other arm
        // (the cert-less arm is modeCRequireRefusesTheCertlessPeer above).
        SSLSocket unanchored = foreignCertSslSocket(legs, reversePort);
        clients.add(unanchored);
        unanchored.startHandshake();
        assertThatThrownBy(() -> unanchored.getInputStream().read())
                .as("REQUIRE-side PKIX validation refuses the unanchored cert (the reverse's trust "
                        + "store anchors only the fixture CA) — the alert or the close surfaces on the first read")
                .isInstanceOf(java.io.IOException.class);
        assertThat(smsc.sessions())
                .as("no SMPP PDU was ever read — the failure is BELOW the codec (AC4)")
                .isEmpty();
    }

    // ---------------------------------------------------------------- routing miss on the wire (AC2)

    @Test
    @DisplayName("routing miss: the client receives the on-wire AD-33 collapse (header-only "
            + "ESME_RBINDFAIL + close) and NOTHING reaches the reverse")
    void routingMissCollapsesOnTheWire() throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        int reversePort = startReverse(RelayTestFixtures.reverseAProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", smsc.port()));
        int forwardPort = startForward(RelayTestFixtures.forwardAProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", reversePort));

        try (Socket legacy = connectLegacyClient(forwardPort)) {
            writePdu(legacy, bindRequest(3, "intruder", "pw123456"));
            byte[] deny = readPdu(legacy);
            ByteBuffer header = ByteBuffer.wrap(deny);
            assertThat(header.getInt(0)).as("header-only construct").isEqualTo(16);
            assertThat(header.getInt(4)).isEqualTo(BIND_TRANSCEIVER_RESP);
            assertThat(header.getInt(8)).as("the ONE generic bind-failure status (AD-33, literal pin)")
                    .isEqualTo(ESME_RBINDFAIL);
            assertThat(header.getInt(12)).isEqualTo(3);
            // The connection CLOSES after the deny: the next read is EOF, not a hang.
            assertThatThrownBy(() -> readPdu(legacy))
                    .as("'bind_resp error, then close' — the leg must be gone")
                    .isInstanceOf(EOFException.class);
        }
        assertThat(smsc.sessions())
                .as("the miss never dialed the reverse — no SMSC session, no reverse-side bind")
                .isEmpty();
    }

    // ---------------------------------------------------------------- N sessions per system_id

    @Test
    @DisplayName("N sessions per system_id: two concurrent binds under carrierOne each couple to their "
            + "OWN forward->reverse->SMSC chain; per-session deliver_sm lands on EXACTLY its client")
    void twoSessionsSameSystemIdEachCoupleIndependently() throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        int reversePort = startReverse(RelayTestFixtures.reverseAProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", smsc.port()));
        int forwardPort = startForward(RelayTestFixtures.forwardAProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", reversePort));

        try (Socket clientA = connectLegacyClient(forwardPort); Socket clientB = connectLegacyClient(forwardPort)) {
            byte[] bindA = bindRequest(11, "carrierOne", "pw123456");
            byte[] bindB = bindRequest(12, "carrierOne", "pw123456");
            writePdu(clientA, bindA);
            writePdu(clientB, bindB);
            assertRokBindResp(readPdu(clientA), 11);
            assertRokBindResp(readPdu(clientB), 12);

            MockSmsc.pollUntil(() -> smsc.sessions().size() >= 2);
            MockSmsc.Session smppSideA = sessionBoundWith(bindA);
            MockSmsc.Session smppSideB = sessionBoundWith(bindB);
            assertThat(smppSideA).as("one SMSC session per ingress connection — pairing per channel, "
                    + "never per system_id").isNotSameAs(smppSideB);

            byte[] deliverToA = opaquePdu(DELIVER_SM, 601, "DLR-FOR-CLIENT-A");
            byte[] deliverToB = opaquePdu(DELIVER_SM, 602, "DLR-FOR-CLIENT-B");
            smppSideA.deliver(deliverToA);
            smppSideB.deliver(deliverToB);
            assertThat(readPdu(clientA)).isEqualTo(deliverToA);
            assertThat(readPdu(clientB)).isEqualTo(deliverToB);
            assertNoFurtherPdu(clientA);
            assertNoFurtherPdu(clientB);
        }
    }

    // ---------------------------------------------------------------- the F13 cap

    @Test
    @DisplayName("F13 cap: at memory.concurrent-pairs the acceptor REFUSES a further connection (close, no response)")
    void capRefusesConnectionsOverTheLimit() throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        int reversePort = startReverse(RelayTestFixtures.reverseAProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", smsc.port()));
        // cap=1: the FIRST connection is served; the second is refused at the acceptor.
        ProxyCompanionProperties forward = RelayTestFixtures.forwardAProperties(
                RelayTestFixtures.freePort(), 1, legs, "127.0.0.1", reversePort);
        int forwardPort = startForward(forward);

        try (Socket first = connectLegacyClient(forwardPort)) {
            writePdu(first, bindRequest(21, "carrierOne", "pw123456"));
            assertRokBindResp(readPdu(first), 21); // the cap did not disturb the live connection

            Socket second = connectLegacyClient(forwardPort);
            clients.add(second);
            writePdu(second, bindRequest(22, "carrierOne", "pw123456"));
            // closeForcibly on a socket with unread inbound bytes sends an RST (not a FIN), so the
            // refused client observes a reset rather than a clean EOF — either way: no response PDU,
            // no hang, and the leg is gone.
            assertThatThrownBy(() -> readPdu(second))
                    .as("the over-cap connection is refused (reset/closed) — no response PDU, no hang")
                    .isInstanceOf(java.io.IOException.class);
            assertThat(smsc.sessions())
                    .as("the refused connection never reached the reverse (still exactly one SMSC session)")
                    .hasSize(1);
            // The first connection is unaffected by the refusal.
            byte[] deliver = opaquePdu(DELIVER_SM, 611, "DLR-AFTER-REFUSAL");
            smsc.awaitSession(0).deliver(deliver);
            assertThat(readPdu(first)).isEqualTo(deliver);

            // Recovery (review 2026-08-27): the cap counts LIVE legs, not cumulative accepts —
            // after `first` closes, the exactly-once decrement on the child closeFuture must return
            // capacity. (Neutering that decrement degrades the cap to N-total-per-process-lifetime
            // while every over-cap test above still passes.)
            first.close();
            Socket third = connectLegacyClient(forwardPort);
            writePdu(third, bindRequest(23, "carrierOne", "pw123456"));
            assertRokBindResp(readPdu(third), 23);
        }
    }

    // ---------------------------------------------------------------- F13 bind.host scoping

    @Test
    @DisplayName("F13 bind.host: the acceptor binds the CONFIGURED interface — a sibling loopback "
            + "address is refused (a wildcard-bind regression would accept it)")
    void bindHostScopesTheListener() throws IOException {
        // The fixtures bind DEFAULT_BIND_HOST=127.0.0.1 (the F13 knob under test). Linux serves the
        // whole 127/8 on loopback, so 127.0.0.2 is connectable IFF the acceptor bound a wildcard —
        // reverting to bind(port) alone keeps every other suite green (they all dial 127.0.0.1).
        int port = startReverse(RelayTestFixtures.modeBProperties(
                RelayTestFixtures.freePort(), 1, "127.0.0.1", smsc.port()));
        try (Socket configured = new Socket(InetAddress.getLoopbackAddress(), port)) {
            assertThat(configured.isConnected()).as("the configured interface accepts").isTrue();
        }
        Socket probe = new Socket();
        clients.add(probe);
        assertThatThrownBy(() -> probe.connect(new java.net.InetSocketAddress("127.0.0.2", port), 2_000))
                .as("the listener is scoped to 127.0.0.1 — a sibling loopback alias must be refused")
                .isInstanceOf(java.io.IOException.class);
    }

    // ---------------------------------------------------------------- AD-28 delegated-task executor

    @Test
    @DisplayName("AD-28: delegated handshake tasks execute on the factory's EXECUTOR threads — "
            + "never silently on the relay event loop")
    void delegatedHandshakeTasksRunOnTheExecutor() throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        List<String> delegatedOn = Collections.synchronizedList(new ArrayList<>());
        // The recording stand-in for the production bounded pool: every submitted delegated task
        // runs on its own thread so WHERE it ran is observable (Runnable::run would hide it).
        Executor recording = task -> {
            Thread runner = new Thread(task, "ad28-delegate");
            delegatedOn.add(runner.getName());
            runner.start();
        };
        int reversePort = startRelay(RelayTestFixtures.reverseAProperties(
                RelayTestFixtures.freePort(), 64, legs, "127.0.0.1", smsc.port()), recording);

        SSLSocket client = trustOnlySslSocket(legs, reversePort);
        clients.add(client);
        client.startHandshake(); // completes: the fixture CA anchors the server cert
        client.close();

        assertThat(delegatedOn)
                .as("the RSA server-cert handshake delegates work through the executor the factory "
                        + "carries (the SslHandler wiring the production bean's pool relies on)")
                .isNotEmpty();
        assertThat(delegatedOn)
                .as("no delegated task ran on the relay event loop thread")
                .noneMatch(thread -> thread.startsWith("tls-e2e-relay"));
    }

    // ---------------------------------------------------------------- Mode B regression

    @Test
    @DisplayName("Mode B regression: the plaintext direct-leg cell is byte-compatible with Story 2.2 "
            + "(bind -> ROK -> byte-exact at the SMSC)")
    void modeBRegression() throws IOException {
        int reversePort = startReverse(RelayTestFixtures.modeBProperties(
                RelayTestFixtures.freePort(), 1, "127.0.0.1", smsc.port()));

        try (Socket legacy = connectLegacyClient(reversePort)) {
            byte[] bind = bindRequest(31, "legacy1", "pw123456");
            writePdu(legacy, bind);
            assertRokBindResp(readPdu(legacy), 31);
            assertThat(smsc.awaitSession(0).bindFrame())
                    .as("reverse.mode-b relays the original bind verbatim, unchanged by the [B] sweep")
                    .isEqualTo(bind);
        }
    }

    // ---------------------------------------------------------------- harness

    /** Starts the reverse-role acceptor (internet-leg TLS listener in a/c; plaintext direct leg in b). */
    private int startReverse(ProxyCompanionProperties properties) {
        return startRelay(properties);
    }

    /** Starts the forward-role acceptor (plaintext trusted-leg listener; dials the routing target). */
    private int startForward(ProxyCompanionProperties properties) {
        return startRelay(properties);
    }

    private int startRelay(ProxyCompanionProperties properties) {
        return startRelay(properties, Runnable::run);
    }

    /** The AD-28 variant: boots the relay with the factory carrying the caller's delegated-task executor. */
    private int startRelay(ProxyCompanionProperties properties, Executor delegatedTaskExecutor) {
        RelayTestFixtures.RelayHarness harness = RelayTestFixtures.relayHarness(
                properties, new AlwaysAllowBindCredentialVerifier(), delegatedTaskExecutor);
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(
                1, new DefaultThreadFactory("tls-e2e-relay"), NioIoHandler.newFactory());
        groups.add(group);
        RelayServerLifecycle lifecycle = new RelayServerLifecycle(
                properties, group,
                new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                harness.ingressInitializer());
        lifecycles.add(lifecycle);
        lifecycle.start();
        assertThat(lifecycle.isRunning()).as("precondition: the acceptor is up").isTrue();
        return properties.bind().port();
    }

    /** The REQUIRE-negative probe: a JDK TLS client trusting the fixture CA, presenting NO cert. */
    private static SSLSocket trustOnlySslSocket(RelayTestFixtures.SmppTlsLegs legs, int port) throws IOException {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, fixtureTrustManagers(legs), null);
            SSLSocketFactory factory = context.getSocketFactory();
            return (SSLSocket) factory.createSocket(InetAddress.getLoopbackAddress(), port);
        } catch (Exception e) {
            throw new IllegalStateException("could not build the cert-less TLS probe", e);
        }
    }

    /**
     * The AC4 unanchored probe: same fixture-CA trust as {@link #trustOnlySslSocket}, but PRESENTING
     * the foreign-CA-chained client pair ({@code generate.sh} §10 — verified: chains to foreign-ca.pem,
     * "error 20" under the fixture CA). The JDK KeyManager is built straight from the PEMs — the
     * committed key is PKCS#8 ("BEGIN PRIVATE KEY"), so it parses with {@link java.security.KeyFactory}
     * alone; the cert with X.509 CertificateFactory. No keystore tooling, no PEM library.
     */
    private static SSLSocket foreignCertSslSocket(RelayTestFixtures.SmppTlsLegs legs, int port) throws IOException {
        try {
            PrivateKey key = pemPrivateKey(legs.foreignClientKey());
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(java.nio.file.Files.newInputStream(legs.foreignClientCert()));
            KeyStore identity = KeyStore.getInstance(KeyStore.getDefaultType());
            identity.load(null, null);
            identity.setKeyEntry("foreign", key, new char[0], new java.security.cert.Certificate[] {cert});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(identity, new char[0]);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), fixtureTrustManagers(legs), null);
            SSLSocketFactory factory = context.getSocketFactory();
            return (SSLSocket) factory.createSocket(InetAddress.getLoopbackAddress(), port);
        } catch (Exception e) {
            throw new IllegalStateException("could not build the unanchored-cert TLS probe", e);
        }
    }

    /** The fixture-CA trust managers shared by both REQUIRE-negative probes. */
    private static javax.net.ssl.TrustManager[] fixtureTrustManagers(RelayTestFixtures.SmppTlsLegs legs)
            throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = java.nio.file.Files.newInputStream(legs.trustStore())) {
            trustStore.load(in, RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        return tmf.getTrustManagers();
    }

    /** Parses a PKCS#8 PEM private key ("BEGIN PRIVATE KEY") with the JDK alone. */
    private static PrivateKey pemPrivateKey(Path pem) throws Exception {
        String body = java.nio.file.Files.readString(pem).replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] encoded = java.util.Base64.getDecoder().decode(body);
        return java.security.KeyFactory.getInstance("RSA")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(encoded));
    }

    private Socket connectLegacyClient(int port) throws IOException {
        Socket socket = new Socket(InetAddress.getLoopbackAddress(), port);
        socket.setSoTimeout(8_000);
        clients.add(socket); // @AfterEach closes whatever the test itself did not
        return socket;
    }

    private MockSmsc.Session sessionBoundWith(byte[] bind) {
        return smsc.sessions().stream()
                .filter(s -> Arrays.equals(s.bindFrame(), bind))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no SMSC session captured the given bind bytes"));
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

    // ---------- raw-socket PDU I/O ----------

    private static void writePdu(Socket socket, byte[] pdu) throws IOException {
        socket.getOutputStream().write(pdu);
        socket.getOutputStream().flush();
    }

    private static byte[] readPdu(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] header = in.readNBytes(16);
        if (header.length < 16) {
            throw new EOFException("peer closed mid-header (expected a complete framed PDU)");
        }
        int commandLength = ByteBuffer.wrap(header).getInt(0);
        if (commandLength < 16 || commandLength > (1 << 20)) {
            // Review 2026-08-27: fail LOUDLY on an implausible harness-side frame (the known jSMPP
            // oracle trap class — a malformed length would otherwise surface as AIOOBE or a giant
            // allocation), instead of trusting whatever the header claimed.
            throw new EOFException("implausible command_length in peer header: " + commandLength);
        }
        byte[] pdu = Arrays.copyOf(header, commandLength);
        int body = in.readNBytes(pdu, 16, commandLength - 16);
        if (body < commandLength - 16) {
            throw new EOFException("peer closed mid-body (partial frame reached the wire!)");
        }
        return pdu;
    }

    private static void assertRokBindResp(byte[] resp, int expectedSequence) {
        ByteBuffer header = ByteBuffer.wrap(resp);
        assertThat(header.getInt(0)).as("the resp's command_length covers the whole PDU").isEqualTo(resp.length);
        assertThat(header.getInt(4)).as("bind_transceiver answered by bind_transceiver_resp")
                .isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(header.getInt(8)).as("ESME_ROK — the bind coupled across BOTH proxies + TLS").isZero();
        assertThat(header.getInt(12)).as("the resp answers the request's sequence_number").isEqualTo(expectedSequence);
    }

    private static void assertNoFurtherPdu(Socket socket) throws IOException {
        int original = socket.getSoTimeout();
        socket.setSoTimeout(300);
        try {
            int first = socket.getInputStream().read();
            if (first < 0) {
                throw new AssertionError("the relay closed the leg — expected a live spliced pair");
            }
            throw new AssertionError("an extra byte arrived — a duplicate or cross-bled PDU (first byte " + first + ")");
        } catch (SocketTimeoutException clean) {
            // nothing further arrived — the pass condition
        } finally {
            socket.setSoTimeout(original);
        }
    }
}
