package smpp.companion.proxy.bootstrap;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.util.AsciiString;
import io.netty.util.concurrent.DefaultThreadFactory;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.relay.MockSmsc;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.security.AdjudicationLifecycle;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.IdpSslContextFactory;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.RopcBindCredentialVerifier;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;
import smpp.companion.proxy.testsupport.OidcDiscoveryStandIn;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Story 4.2 T4 — the AD-22 walk under RACE, over the REAL stack: a legacy loopback socket through
 * the REAL acceptor and ingress pipeline, the REAL ROPC adapter parked mid-exchange at an in-process
 * TLS stand-in IdP, and the REAL Spring stop order — all five beans ({@code RelayServerLifecycle},
 * {@code AdjudicationLifecycle}, {@code ProxyCompanionLifecycle}, the group bean's
 * {@code destroyMethod="shutdownGracefully"} backstop, the adapter bean's fused {@code close()}
 * backstop) registered in an {@link AnnotationConfigApplicationContext}, whose {@code close()} IS
 * the SIGTERM-equivalent (ContextClosedEvent &rarr; DefaultLifecycleProcessor &rarr;
 * {@code SmartLifecycle.stop} in DESCENDING phase — exactly what the JVM shutdown hook drives; the
 * phase constants, not this test's hand, sequence the walk).
 *
 * <p>The catalog rows landed here:
 * <ul>
 * <li><b>RELAY-023 / OBS-019 — the Allow racing the deny.</b> The bind's token exchange parks at the
 * stand-in's token endpoint (the latch-held adjudication); the walk fires; the pinned outcome:
 * the client receives its non-ROK {@code bind_resp} (the AD-33 {@code ESME_RBINDFAIL} collapse)
 * BEFORE the close, the couple flag never flips ({@code onBindAccept} never fires; the mock SMSC
 * never sees a session — it ANSWERS ROK, so a transient couple cannot hide), the registry empties,
 * the password zeroizes (the caller-owned wipe at the settle), and the verdict settles
 * {@code DenyIndeterminate}. <b>The race's deterministic half:</b> the armed Allow — a VALID 200 +
 * three-segment JWS — completes only AFTER the walk, onto the dead exchange, and resolves NOTHING
 * (the pin completes exactly once, fail-closed first; AD-11). The other half — the 200 landing in
 * the sub-window between the {@code shutdownNow()} and the exchange's own abort — is not
 * deterministically stageable against this story's mechanics (the parked join ignores the deny
 * interrupt by design, and 4.2 carries no new-adjudication gate); landing a verdict in that window
 * is exactly what 4.3's mutation fence + gate will own. Pinned here is what 4.2 owns: the deny on
 * the LIVE loop, the fail-closed settle, and the once-only pin.</li>
 * <li><b>The matrix row "SIGTERM, coupled pairs mid-splice" + AC3's coupled arm.</b> The
 * IMMEDIATE-answer IdP variant lets the bind genuinely COUPLE (token Allow &rarr; egress dial
 * &rarr; the mock's ROK — the only row in this suite where the couple flag DOES flip); the walk
 * then fires mid-splice and pins the documented 4.2 seam contract: UNCHANGED from today at the
 * seam — the pair tears down at the QUIESCE (no drain body yet, the empty 4.3 seam), both legs
 * die, the registry empties, and the walk still exits inside the meaningful window (the 5s
 * idiom, well under the 30s ceiling).</li>
 * <li><b>OBS-021 — zero orphaned adjudication VTs.</b> The catalog's literal "ThreadMXBean
 * snapshot" is unimplementable as written: JEP 444 excludes virtual threads from
 * {@code Thread.getAllStackTraces()}/{@code ThreadMXBean.getAllThreadIds()} (verified empirically
 * on this JDK; the repo's own observability tier documented the same — "the pool counts itself",
 * {@code ResourceMetrics}). The row keeps its intent via the sanctioned VT-visible seam — the
 * adapter's {@code activeAdjudications()} count (incremented at submit, decremented in each pool
 * task's {@code finally}, rejection-compensated: an adjudication VT that survived the walk would
 * hold it &gt; 0) — plus the joined-walk bound: release's {@code awaitTermination} only returns
 * promptly if the pool drained, so a walk that finished well inside the await budget proves no VT
 * outlived it.</li>
 * <li><b>The ordering prefix pin</b> (the OBS-016 probe's 4.3 extension lands later):
 * acceptor-stopped &le; adjudications-denied &le; vt-released &le; loop-quiesced, observed
 * INDEPENDENTLY of the stop calls by four monotonic probes stamped on one nanoTime timeline —
 * the port rebindable (the acceptor REALLY closed), the in-flight pin settled fail-closed (the
 * deny's effect, stamped by a {@code whenComplete} listener registered BEFORE the relay's own
 * continuation), the VT pool drained to zero, and the shared loop terminated. The middle two are
 * µs-adjacent causal twins (the settle and the pool task's exit), so the prefix is asserted as a
 * chain of windows: the acceptor stop strictly precedes BOTH, BOTH strictly precede the quiesce
 * (margins ~500ms and ~100ms) — never the twins against each other at nanoTime granularity.</li>
 * </ul>
 *
 * <p>Timing idiom (the T3 rows): a SHORT {@code oidc.timeout} budget — the parked exchange aborts
 * at its OWN per-request budget (the forked join ignores the deny interrupt), so the walk is
 * deny(&asymp;0) &rarr; abort(500ms) &rarr; settle+continuation &rarr; release-join &rarr; quiesce
 * (100ms quiet) — never Netty's 2s default, always inside the 30s per-phase ceiling.
 * Class-level {@link Timeout} on a separate thread: sockets + a parked stand-in can hang — a stuck
 * walk must FAIL a test, never stall the suite.
 */
@Tag("integration")
@Tag("bootstrap")
@Tag("p1")
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@DisplayName("Story 4.2 T4 — AD-22 walk races: deny-on-live-loop, VT hygiene, ordering prefix")
@SuppressWarnings("FutureReturnValueIgnored") // reason: the recorder's whenComplete listener is
// fire-and-forget observation — its downstream future is deliberately unobserved (the settle is
// read via the SAME pin future the assertions hold), and the listener itself can never throw.
class GracefulShutdownRacesTest {

    /** The pinned-Keycloak realm token path the stand-in IdP serves (the T3 fixture idiom). */
    private static final String TOKEN_PATH = "/realms/smpp-companions/protocol/openid-connect/token";

    /** The bind_resp wire contract, pinned as LITERALS (the RelayA1SmokeTest discipline). */
    private static final int BIND_TRANSCEIVER = 0x00000009;
    private static final int BIND_TRANSCEIVER_RESP = 0x80000009;

    /** ESME_RBINDFAIL 0x0000000D — the AD-33 generic bind-failure collapse (SMPP 3.4 §5.1.3). */
    private static final int ESME_RBINDFAIL = 0x0000000D;

    /**
     * The SHORT per-request budget (the T3 split-row timing): the parked exchange aborts at its OWN
     * budget — 500ms — and release's await (budget + 1s = 1.5s) JOINS that abort, keeping every walk
     * in this suite fast and its joined-vs-timed-out separation wide (~700ms vs ≥1.6s).
     */
    private static final Duration OIDC_TIMEOUT = Duration.ofMillis(500);

    private static final int OIDC_MAX_IN_FLIGHT = 8;

    @Test
    @DisplayName("RELAY-023/OBS-019: the Allow racing the deny resolves fail-closed — non-ROK bind_resp "
            + "on the live loop, couple never flips, password zeroized; the late armed Allow resolves nothing")
    void allowRacingDenyResolvesFailClosedAndTheClientHoldsTheBindRespError(@TempDir Path dir) throws Exception {
        Rig rig = rig(dir, 1);
        try (Socket legacy = rig.connectLegacy()) {
            writePdu(legacy, bindRequest(7, "legacy1", "pw123456"));
            assertTrue(rig.awaitTokens(),
                    "the adjudication must be in-flight (parked at the token endpoint) when SIGTERM fires");

            rig.ctx.close(); // SIGTERM-equivalent: Spring stops phase 1000 -> 750 -> 0, then the destroy backstops

            // OBS-019: the fail-closed bind_resp reached the client BEFORE the close — the deny's
            // continuation executed on the STILL-LIVE loop (the stranding residue is unreachable).
            assertDenyBindResp(readPdu(legacy), 7);
            assertAtEof(legacy); // "bind_resp error, then close" — the CLOSE listener ran after the write

            // RELAY-023: the couple flag never flipped. The mock ANSWERS ROK, so a couple attempt
            // would surface here: no accept trigger, no SMSC session, no registry entry.
            assertThat(rig.harness.observer().bindAccepts())
                    .as("the latch-held Allow never coupled (no onBindAccept)")
                    .isEmpty();
            assertThat(rig.smsc.sessions())
                    .as("no egress pair ever dialed the SMSC (the couple never began)")
                    .isEmpty();
            assertThat(rig.harness.registry().size())
                    .as("the registry emptied — the deny teardown removed the pair")
                    .isZero();

            // The settle: fail-closed (AD-11) — the deny's forced abort, not a provider verdict.
            assertThat(rig.recorder.requests.get(0).future().getNow(null))
                    .as("a shutdown-denied adjudication settles DenyIndeterminate (AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            // OBS-019: the password zeroized — the caller-owned wipe at the settle (the SAME backing
            // array the relay handed the verifier; the recording delegate captured it).
            assertThat(zeroized(rig.recorder.credentials.get(0).password().value()))
                    .as("the bind password zeroized on the shutdown-deny path")
                    .isTrue();

            // THE RACE, its deterministic half: the armed Allow — a VALID 200 + three-segment JWS —
            // completes only now, onto the dead exchange (release's http.close() already tore it).
            // The pin completes exactly once, fail-closed first: the Allow resolves NOTHING.
            rig.hold.countDown();
            assertStillAtEof(legacy);
            assertThat(rig.recorder.requests.get(0).future().getNow(null))
                    .as("the late Allow cannot flip the settled pin (completes exactly once — AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(rig.harness.observer().bindAccepts())
                    .as("the couple flag still never flipped after the late Allow")
                    .isEmpty();
            assertThat(rig.smsc.sessions()).as("still no SMSC session").isEmpty();
        } finally {
            rig.close(); // idempotent: releases the parked stand-in handlers, stops everything still up
        }
    }

    @Test
    @DisplayName("matrix 'SIGTERM, coupled pairs mid-splice' + AC3's coupled arm: the seam UNCHANGED "
            + "this story — the pair tears down at the quiesce (no drain body yet, 4.3) and the walk "
            + "exits inside the window")
    void coupledPairsMidSpliceTearDownAtTheQuiesceAndExitInsideTheWindow(@TempDir Path dir) throws Exception {
        // The IMMEDIATE-answer IdP variant: the exchange yields Allow, the egress dials, the mock
        // answers ROK — a genuinely COUPLED pair mid-splice when SIGTERM fires.
        Rig rig = rig(dir, 1, false);
        try (Socket legacy = rig.connectLegacy()) {
            byte[] bind = bindRequest(11, "legacy1", "pw123456");
            writePdu(legacy, bind);
            assertRokBindResp(readPdu(legacy), 11); // the full chain: token Allow -> dial -> SMSC ROK

            // The couple REALLY established (the contrast to every other row in this suite): the
            // mock session carries the verbatim bind (AD-14), the pair is live, the flag flipped.
            MockSmsc.Session session = rig.smsc.awaitSession(0);
            assertThat(session.bindFrame())
                    .as("AD-14: the original bind reached the SMSC byte-exact")
                    .isEqualTo(bind);
            assertThat(rig.harness.registry().size())
                    .as("the coupled pair is live mid-splice")
                    .isEqualTo(1);
            assertThat(rig.harness.observer().bindAccepts())
                    .as("the couple flag flipped exactly once")
                    .hasSize(1);

            long start = System.nanoTime();
            rig.ctx.close(); // SIGTERM-equivalent, mid-splice (the drain seam is EMPTY — 4.3 fills it)
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

            // The documented 4.2 seam contract: UNCHANGED from today at the seam — both legs torn
            // at the QUIESCE (never a drain, never a mid-write truncation: the legs close cleanly
            // with the loop), the registry emptied — and the walk still exits fast: an idle-pool
            // deny + an instantly-joined release + the 100ms-quiet quiesce, the Bootstrap 5s
            // idiom, well under the 30s per-phase ceiling.
            assertThat(elapsedMs)
                    .as("the mid-splice walk exits inside the window (no drain body yet — 4.3)")
                    .isLessThan(5_000L);
            assertAtEof(legacy); // the ingress leg died at the quiesce
            awaitTrue("the SMSC session closed by the quiesce", session::closed); // the egress leg with it
            assertThat(rig.harness.registry().size())
                    .as("the pair is gone from the registry")
                    .isZero();
            assertThat(rig.group.isTerminated())
                    .as("the loop is down — the walk completed")
                    .isTrue();
        } finally {
            rig.close();
        }
    }

    @Test
    @DisplayName("OBS-021: zero orphaned adjudication VTs after the walk — the VT-gauge count cannot "
            + "leak and every parked continuation delivered its deny")
    void zeroOrphanedAdjudicationVtsAfterTheWalk(@TempDir Path dir) throws Exception {
        Rig rig = rig(dir, 3);
        List<Socket> clients = new ArrayList<>();
        try {
            for (int i = 0; i < 3; i++) {
                Socket legacy = rig.connectLegacy();
                clients.add(legacy);
                writePdu(legacy, bindRequest(100 + i, "legacy1", "pw123456"));
            }
            assertTrue(rig.awaitTokens(), "all three adjudications must be in-flight when SIGTERM fires");
            // Sanity (the probe must be ABLE to see them): the pool counts 3 in-flight adjudications.
            assertThat(rig.adapter.activeAdjudications())
                    .as("precondition: three live adjudication VTs (the VT-gauge seam)")
                    .isEqualTo(3);

            long start = System.nanoTime();
            rig.ctx.close(); // the walk: shutdownNow interrupts all three; each aborts at its own budget
            long walkMs = (System.nanoTime() - start) / 1_000_000L;

            // Every cancelled continuation executed on the live loop: each client holds its deny.
            for (int i = 0; i < 3; i++) {
                assertDenyBindResp(readPdu(clients.get(i)), 100 + i);
                assertAtEof(clients.get(i));
            }
            // Zero orphaned adjudication VTs: the count decrements only in each pool task's finally —
            // a surviving VT would hold it > 0 (ThreadMXBean cannot see VTs; JEP 444 — see class doc).
            assertThat(rig.adapter.activeAdjudications())
                    .as("post-walk: zero adjudication VTs survive (OBS-021)")
                    .isZero();
            assertThat(rig.harness.observer().bindAccepts()).isEmpty();
            assertThat(rig.harness.registry().size()).isZero();
            // The joined-walk bound: release's awaitTermination(budget+1s) returned PROMPTLY (the
            // pool drained) — a surviving VT would floor the walk at the full await + the warn.
            assertThat(walkMs)
                    .as("the walk finished inside the release-await budget (the pool provably joined)")
                    .isLessThan(OIDC_TIMEOUT.plusSeconds(1).toMillis());
        } finally {
            clients.forEach(socket -> {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // teardown best-effort — the walk's own close is what the test asserts
                }
            });
            rig.close();
        }
    }

    @Test
    @DisplayName("ordering prefix: acceptor-stopped ≤ adjudications-denied ≤ vt-released ≤ "
            + "loop-quiesced — four monotonic probes on one timeline, independent of the stop calls")
    void theWalksOrderingPrefixAcceptorDeniedReleasedQuiesced(@TempDir Path dir) throws Exception {
        // A LONG per-request budget for THIS row (4.2 review, not the suite's 500ms idiom): the
        // pinned exchange self-aborts at its OWN budget, so a 500ms budget races the watcher arming
        // and the acceptor stop (a slow runner between awaitTokens() and ctx.close() would settle
        // the pin BEFORE the acceptor stopped → t1 < t2 false-RED). 3s makes the arming race
        // unwinnable and widens every watcher's stamp margin from ~100ms to seconds.
        Rig rig = rig(dir, 1, true, Duration.ofSeconds(3));
        ExecutorService watchers = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "shutdown-race-watcher");
            t.setDaemon(true);
            return t;
        });
        try (Socket legacy = rig.connectLegacy()) {
            writePdu(legacy, bindRequest(9, "legacy1", "pw123456"));
            assertTrue(rig.awaitTokens(), "the adjudication must be in-flight when SIGTERM fires");

            // Armed BEFORE the walk; each stamps the FIRST time its monotonic predicate holds, so a
            // stamp can only run LATE, never early — the asserted chain is conservative.
            Future<Long> acceptorStopped = watchers.submit(() -> pollStamp("the acceptor port freed",
                    () -> portFree(rig.relayPort)));
            Future<Long> adjudicationsDenied = watchers.submit(() -> pollStamp(
                    "the in-flight adjudication settled fail-closed",
                    () -> !rig.recorder.settleStamps.isEmpty()));
            Future<Long> vtReleased = watchers.submit(() -> pollStamp("the adjudication VT pool drained",
                    () -> rig.adapter.activeAdjudications() == 0));
            Future<Long> loopQuiesced = watchers.submit(() -> pollStamp("the shared relay loop terminated",
                    rig.group::isTerminated));

            rig.ctx.close(); // SIGTERM-equivalent — the phases, not this hand, order the walk

            long t1 = acceptorStopped.get(20, TimeUnit.SECONDS);
            long t2 = adjudicationsDenied.get(20, TimeUnit.SECONDS);
            long t3 = vtReleased.get(20, TimeUnit.SECONDS);
            long t4 = loopQuiesced.get(20, TimeUnit.SECONDS);

            // The deny's effect is fail-closed (not a provider verdict) — the probe saw the REAL settle.
            assertThat(rig.recorder.settleVerdicts.get(0))
                    .as("the settle the ordering probe observed is the fail-closed deny")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            // The prefix pin, as a CHAIN OF WINDOWS (the spec's ≤ chain): the acceptor stop
            // strictly precedes BOTH middle observables, and BOTH strictly precede the loop's
            // death — so acceptor-stopped < {adjudications-denied, vt-released} < loop-quiesced.
            // The two middle observables themselves are µs-adjacent causal twins (the pool task
            // settles the pin and exits; a concurrent cancelHttp settle can complete the pin on
            // the relay's thread instead — either fail-closed arm winning that µs race is
            // contract-identical), so they are asserted as one window, never against each other.
            assertThat(t1).as("step 1: the acceptor stopped before the adjudications were denied")
                    .isLessThan(t2);
            assertThat(t1).as("step 1: the acceptor stopped before the VT pool released")
                    .isLessThan(t3);
            assertThat(t2).as("steps 2->5: the adjudications denied before the loop quiesced")
                    .isLessThan(t4);
            assertThat(t3).as("steps 4->5: the VT pool released before the loop quiesced")
                    .isLessThan(t4);
            // The end state the walk owes, and the client-visible outcome.
            assertThat(rig.group.isTerminated()).as("the walk awaited the loop's death").isTrue();
            assertThat(rig.adapter.activeAdjudications()).isZero();
            assertDenyBindResp(readPdu(legacy), 9);
            assertAtEof(legacy);
        } finally {
            watchers.shutdownNow();
            rig.close();
        }
    }

    // ── the rig: the real stack wired into a real Spring stop order ───────────────────────────

    /** Everything one row needs; {@link #close()} is idempotent and exception-safe. */
    private record Rig(
            MockSmsc smsc,
            HttpsServer idp,
            CountDownLatch tokenReceived,
            CountDownLatch hold,
            EventLoopGroup group,
            RopcBindCredentialVerifier adapter,
            RecordingVerifier recorder,
            RelayTestFixtures.RelayHarness harness,
            RelayServerLifecycle relay,
            AdjudicationLifecycle adjudication,
            ProxyCompanionLifecycle coordinator,
            AnnotationConfigApplicationContext ctx,
            int relayPort) {

        /** A legacy loopback client on the real acceptor (the RelayA1SmokeTest idiom). */
        Socket connectLegacy() throws IOException {
            Socket socket = new Socket(InetAddress.getLoopbackAddress(), relayPort);
            socket.setSoTimeout(4_000);
            return socket;
        }

        /** Waits until the stand-in IdP has parked every expected token exchange. */
        boolean awaitTokens() throws InterruptedException {
            // the shared latch was sized at rig build: each parked exchange counts it down once
            return tokenReceived.await(5, TimeUnit.SECONDS);
        }

        /** Best-effort, idempotent teardown — never strands the port, the IdP, the mock, or the loop. */
        void close() {
            hold.countDown(); // release any parked stand-in handlers
            try {
                idp.stop(0);
            } catch (Exception ignored) {
                // already stopped
            }
            try {
                smsc.close();
            } catch (Exception ignored) {
                // already closed
            }
            try {
                ctx.close(); // idempotent (the walk's normal path already closed it)
            } catch (Exception ignored) {
                // a failed refresh/close must not mask the test's own assertion
            }
            group.shutdownGracefully().syncUninterruptibly(); // re-fire: a no-op after the walk
        }
    }

    /**
     * The race rows' rig: the PARKED-allow stand-in IdP (the latch-held adjudication).
     * See {@link #rig(Path, int, boolean)}.
     */
    private static Rig rig(Path dir, int tokenCount) throws IOException {
        return rig(dir, tokenCount, true, OIDC_TIMEOUT);
    }

    private static Rig rig(Path dir, int tokenCount, boolean park) throws IOException {
        return rig(dir, tokenCount, park, OIDC_TIMEOUT);
    }

    /**
     * Builds the whole rig: the mock SMSC (it ANSWERS ROK — a couple attempt cannot hide), the
     * stand-in IdP (PARKED for the race rows, IMMEDIATE for the coupled-pairs row), the shared
     * loop, the REAL adapter, the real ingress wiring behind a {@link RecordingVerifier} (the
     * relay-facing half — production wires ONE verifier bean; the recorder is a pass-through that
     * only captures the credential and the settle, the OBS-019 tooling), and the three lifecycles
     * + the two destroy backstops as Spring beans so {@code ctx.close()} walks the REAL phase
     * order.
     */
    private static Rig rig(Path dir, int tokenCount, boolean park, Duration oidcTimeout)
            throws IOException {
        MockSmsc smsc = MockSmsc.start();
        CountDownLatch tokenReceived = new CountDownLatch(tokenCount);
        CountDownLatch hold = new CountDownLatch(1);
        HttpsServer idp = allowIdp(tokenReceived, hold, park);
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(
                // daemon: a test that times out wedged inside the uninterruptible walk never runs its
                // finally — a non-daemon loop thread would then outlive the failure and hang the JVM.
                1, new DefaultThreadFactory("shutdown-race-relay", true), NioIoHandler.newFactory());
        AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext();
        try {
            ProxyCompanionProperties properties =
                    reverseBProperties(dir, realmBase(idp), smsc.port(), oidcTimeout);
            IdpSslContextFactory tlsFactory = new IdpSslContextFactory(properties);
            RopcBindCredentialVerifier adapter = new RopcBindCredentialVerifier(tlsFactory);
            RecordingVerifier recorder = new RecordingVerifier(adapter);
            RelayTestFixtures.RelayHarness harness = RelayTestFixtures.relayHarness(properties, recorder);
            RelayServerLifecycle relay = new RelayServerLifecycle(properties, group,
                    new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                    harness.ingressInitializer());
            AdjudicationLifecycle adjudication = new AdjudicationLifecycle(adapter);
            ProxyCompanionLifecycle coordinator = new ProxyCompanionLifecycle(adapter, group);

            // The production bean set the stop order needs — the group bean's destroyMethod backstop
            // (RelayNettyConfig) and the adapter bean's fused close() backstop included, so a full
            // close() exercises their re-fire-as-no-op contract too.
            ctx.registerBean(EventLoopGroup.class, () -> group,
                    bd -> ((AbstractBeanDefinition) bd).setDestroyMethodName("shutdownGracefully"));
            ctx.registerBean(RopcBindCredentialVerifier.class, () -> adapter,
                    bd -> ((AbstractBeanDefinition) bd).setDestroyMethodName("close"));
            ctx.registerBean(RelayServerLifecycle.class, () -> relay);
            ctx.registerBean(AdjudicationLifecycle.class, () -> adjudication);
            ctx.registerBean(ProxyCompanionLifecycle.class, () -> coordinator);
            ctx.refresh(); // starts ascending (coordinator 0, deny window 750, acceptor 1000 — the port binds)

            assertThat(relay.isRunning()).as("precondition: the real acceptor is up").isTrue();
            return new Rig(smsc, idp, tokenReceived, hold, group, adapter, recorder, harness,
                    relay, adjudication, coordinator, ctx, properties.bind().port());
        } catch (RuntimeException | Error e) {
            // A rig that fails to build must not strand what it already created (4.2 review): the
            // caller's try/finally never engages when the rig never returns — release it HERE.
            hold.countDown();
            try {
                ctx.close();   // safe unrefreshed (a no-op); walks the stop order if refresh half-ran
            } catch (Exception ignored) {
                // teardown best-effort — the build failure is the signal
            }
            try {
                idp.stop(0);
            } catch (Exception ignored) {
                // already stopped
            }
            try {
                smsc.close();
            } catch (Exception ignored) {
                // already closed
            }
            group.shutdownGracefully().syncUninterruptibly();
            throw e;
        }
    }

    /**
     * The relay-facing verifier: a pass-through over the REAL adapter that records the credential
     * (the OBS-019 password-zeroize probe — the SAME backing array the relay's settle wipe zeroes)
     * and the verdict request (stamping the settle BEFORE the relay registers its own continuation,
     * so the ordering probe sees the settle no later than the relay does). The LIFECYCLES keep the
     * raw adapter — {@code AdjudicationLifecycle}'s deny and the coordinator's halves must fire on
     * the real pool (their {@code instanceof RopcBindCredentialVerifier} key).
     */
    private static final class RecordingVerifier implements BindCredentialVerifier {

        private final RopcBindCredentialVerifier delegate;

        /** Every credential the relay adjudicated, in arrival order (the zeroize probe reads these). */
        final List<BindCredential> credentials = new CopyOnWriteArrayList<>();

        /** Every verdict request returned to the relay, in arrival order. */
        final List<VerdictRequest> requests = new CopyOnWriteArrayList<>();

        /** NanoTime of each settle, stamped by a listener registered before the relay's own. */
        final List<Long> settleStamps = new CopyOnWriteArrayList<>();

        /** What each settle carried (the verdict, or the exceptional future's error). */
        final List<Object> settleVerdicts = new CopyOnWriteArrayList<>();

        RecordingVerifier(RopcBindCredentialVerifier delegate) {
            this.delegate = delegate;
        }

        @Override
        public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
            credentials.add(cred);
            VerdictRequest request = delegate.verify(cred, ctx);
            requests.add(request);
            request.future().whenComplete((verdict, error) -> {
                settleStamps.add(System.nanoTime());
                settleVerdicts.add(error != null ? error : verdict);
            });
            return request;
        }
    }

    // ── the stand-in IdP (the ProxyCompanionLifecycleTest pattern + the ARMED ALLOW) ──────────

    /**
     * A stand-in IdP whose TOKEN handler answers a VALID 200 + three-segment-JWS
     * {@code access_token} — a genuine {@code Allow}. The PARKED variant ({@code park = true}, the
     * race rows) holds that response on a latch — the bind is in-flight until the test releases it
     * (or the walk's deny forces the exchange's own abort), and the late write onto the dead
     * exchange is the race's deterministic half. The IMMEDIATE variant ({@code park = false}, the
     * coupled-pairs row) answers without parking, so the exchange yields {@code Allow} and the
     * bind COUPLES to the mock SMSC. Daemon executor (a parked handler must not strand the JVM).
     */
    private static HttpsServer allowIdp(CountDownLatch tokenReceived, CountDownLatch hold, boolean park)
            throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(OidcDiscoveryStandIn.fixtureServerSslContext()));
        server.setExecutor(Executors.newFixedThreadPool(6, r -> {
            Thread t = new Thread(r, "shutdown-race-idp");
            t.setDaemon(true);
            return t;
        }));
        server.createContext(TOKEN_PATH, ex -> {
            tokenReceived.countDown();
            drain(ex);
            try {
                if (park) {
                    hold.await(15, TimeUnit.SECONDS); // park: the adjudication is in-flight when the walk begins
                }
                respond(ex, 200, "{\"access_token\":\"aa.bb.cc\",\"token_type\":\"Bearer\"}");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                // best-effort late write on the dead exchange — not a verdict signal
            }
        });
        server.start();
        return server;
    }

    /** A reverse×B properties record: the SMSC targeted at the mock, the provider at the stand-in. */
    private static ProxyCompanionProperties reverseBProperties(
            Path dir, String realmBase, int smscPort, Duration oidcTimeout) throws IOException {
        Path store = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "smpp-confidential-secret");
        return new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(
                        RelayTestFixtures.freePort(), RelayTestFixtures.DEFAULT_BIND_HOST,
                        RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE),
                // concurrent-pairs 8 (>= the row's binds): the F13 acceptor cap shares this number.
                new ProxyCompanionProperties.Memory(
                        1, 8, 1.0, ProxyCompanionProperties.Memory.BudgetCheck.FAIL),
                new ProxyCompanionProperties.Tls(
                        List.of("TLSv1.3", "TLSv1.2"),
                        List.of("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
                        List.of("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256")),
                null,
                new ProxyCompanionProperties.Reverse(null, new ProxyCompanionProperties.ReverseModeB(
                        new ProxyCompanionProperties.Smsc("127.0.0.1", smscPort), true,
                        new ProxyCompanionProperties.Oidc(
                                URI.create(realmBase), "smpp-client-confidential", secret.toString(),
                                new ProxyCompanionProperties.TrustStore(store.toString(),
                                        RelayTestFixtures.IDP_STORE_PASSWORD),
                                oidcTimeout, OIDC_MAX_IN_FLIGHT)), null),
                null);
    }

    private static String realmBase(HttpsServer server) {
        return "https://localhost:" + server.getAddress().getPort() + "/realms/smpp-companions";
    }

    // ── probes, stamps, and hand-authored wire bytes (the RelayA1SmokeTest idiom) ────────────

    /**
     * Bounded poll for a monotonic predicate (the {@code MockSmsc.pollUntil} idiom — that helper
     * is package-private to {@code relay/}, so this suite carries its own): awaits {@code probe},
     * failing after 5s rather than hanging.
     */
    private static void awaitTrue(String what, BooleanSupplier probe) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!probe.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("never observed: " + what);
            }
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted while awaiting: " + what, e);
            }
        }
    }

    /** Polls {@code probe} every 5ms until it holds; returns the stamp (fails, never hangs). */
    private static long pollStamp(String what, BooleanSupplier probe) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (!probe.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("the walk watcher never observed: " + what);
            }
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted while watching: " + what, e);
            }
        }
        return System.nanoTime();
    }

    /**
     * {@code true} iff the port can be (re)bound by a LISTENER — the acceptor REALLY closed it
     * (Netty 4.2 completes the close future ~ms before the OS releases the listen socket, which
     * the poller rides out; a genuinely-held port never binds). SO_REUSEADDR on the probe (set
     * before bind): a TIME_WAIT left by a connection the port legitimately served must not fail
     * the probe, while an actual LISTENER (what the pin is about) still refuses.
     */
    private static boolean portFree(int port) {
        try (ServerSocket ignored = rebindableProbe(port)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** A listen-socket probe with SO_REUSEADDR armed BEFORE the bind (see {@link #portFree}). */
    private static ServerSocket rebindableProbe(int port) throws IOException {
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(port));
        return socket;
    }

    /** {@code true} iff every value octet of the (shared-backing) password {@link AsciiString} is zero. */
    private static boolean zeroized(AsciiString value) {
        byte[] array = value.array();
        for (int i = value.arrayOffset(); i < value.arrayOffset() + value.length(); i++) {
            if (array[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /** A hand-authored {@code bind_transceiver} (raw bytes — independent of the codec under test). */
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

    private interface BodyWriter {
        void writeTo(ByteBuffer out);
    }

    private static byte[] assemble(int commandId, int commandStatus, int sequence, int bodyLen,
            BodyWriter writer) {
        ByteBuffer out = ByteBuffer.allocate(16 + bodyLen);
        out.putInt(16 + bodyLen).putInt(commandId).putInt(commandStatus).putInt(sequence);
        writer.writeTo(out);
        return out.array();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    // ── raw-socket PDU I/O + the pinned deny contract (literals, independent of production) ───

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
        // Sanity bounds (4.2 review): < 16 is unframed; > 64KB cannot be a bind_resp this suite
        // reads — a garbage frame from the relay under test must FAIL THE READ, never steer a
        // copyOf into a ~2GB allocation that OOMs the test JVM instead of failing the test.
        if (commandLength < 16 || commandLength > 65_536) {
            throw new IOException("nonsense command_length " + commandLength + " on the wire");
        }
        byte[] pdu = java.util.Arrays.copyOf(header, commandLength);
        int body = in.readNBytes(pdu, 16, commandLength - 16);
        if (body < commandLength - 16) {
            throw new EOFException("peer closed mid-body (partial frame reached the wire!)");
        }
        return pdu;
    }

    /** The pinned ROK contract (the RelayA1SmokeTest literals) — the couple's premise at this leg. */
    private static void assertRokBindResp(byte[] resp, int expectedSequence) {
        ByteBuffer header = ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the resp's command_length covers the whole PDU").isEqualTo(resp.length);
        assertThat(commandId).as("bind_transceiver answered by bind_transceiver_resp")
                .isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(commandStatus).as("ESME_ROK — the SMSC's verbatim answer reached the client (the couple)")
                .isZero();
        assertThat(sequence).as("the resp answers the request's sequence_number").isEqualTo(expectedSequence);
    }

    /** The pinned AD-33 deny contract, asserted on LITERALS (independent of the production constants). */
    private static void assertDenyBindResp(byte[] resp, int expectedSequence) {
        ByteBuffer header = ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the deny is the ONE header-only 16-octet PDU the relay builds")
                .isEqualTo(16).isEqualTo(resp.length);
        assertThat(commandId).as("bind_transceiver answered by bind_transceiver_resp")
                .isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(commandStatus).as("non-ROK: ESME_RBINDFAIL — the AD-33 generic fail-closed deny")
                .isEqualTo(ESME_RBINDFAIL);
        assertThat(sequence).as("the deny answers the request's sequence_number").isEqualTo(expectedSequence);
    }

    /** The relay closed AFTER writing the deny ("bind_resp error, then close"). */
    private static void assertAtEof(Socket socket) throws IOException {
        socket.setSoTimeout(2_000);
        assertThat(socket.getInputStream().read())
                .as("the relay closed the leg after the deny write (never before it)")
                .isEqualTo(-1);
    }

    /** Nothing further EVER arrives on the closed leg (the late Allow reached no one). */
    private static void assertStillAtEof(Socket socket) throws IOException {
        assertAtEof(socket);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static void drain(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
    }
}
