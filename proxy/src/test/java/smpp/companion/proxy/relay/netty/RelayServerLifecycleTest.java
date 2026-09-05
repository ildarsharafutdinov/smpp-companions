package smpp.companion.proxy.relay.netty;

import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.util.concurrent.DefaultThreadFactory;

import smpp.companion.proxy.ProxyCompanionApplication;
import smpp.companion.proxy.bootstrap.ProxyCompanionLifecycle;
import smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier;
import smpp.companion.proxy.testsupport.OidcDiscoveryStandIn;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AC4 (AD-1/AD-2/AD-16) &mdash; the relay's SMPP acceptor {@code SmartLifecycle}: binds
 * {@code companion.bind.port} for the reverse.mode-b cell (this story's slice), stays inert for every
 * other cell, fails the boot fail-fast when the port is occupied (AD-17), and stops BEFORE
 * {@code ProxyCompanionLifecycle} (AD-22 step 1 &mdash; the deferred-work 2nd-SmartLifecycle ordering
 * item) with the stop callback invoked in {@code finally}, the port deterministically released, and
 * the shared loop LEFT LIVE (Story 4.2 T2: stop() is acceptor-close only &mdash; the quiesce belongs
 * to the shutdown coordinator, asserted at full-app close instead).
 * The full-boot tests drive the REAL component-scan wiring via {@code ProxyCompanionApplication}
 * (no slice runner) so the bean's presence in the scanned context is proven, not assumed.
 *
 * <p>Port discipline: every boot uses a freshly-probed ephemeral port as a run-arg (HIGHEST
 * precedence &mdash; it must beat application.yml's shipped {@code bind.port: 2775}; a
 * {@code .properties()} default would LOSE to yml, the T5 lesson), so the tests never collide with a
 * real 2775 listener or each other. Every direct-construction test releases its acceptor + group in a
 * {@code finally} (the exception-safety discipline: a failing assertion must not strand the port).
 */
@Tag("integration")
@Tag("relay")
@Tag("p1")
class RelayServerLifecycleTest {

    @Test
    @DisplayName("mode-b full boot: acceptor binds, serves TCP, runs on named platform threads, stop releases the port")
    void modeBFullAppBootsAcceptorBindsAndStopsCleanly(@TempDir Path dir) throws IOException {
        int port = RelayTestFixtures.freePort();
        EventLoopGroup group;
        RelayServerLifecycle relay;
        // T9 boot boundary (chunk-B review 2026-09-01): this row's provider-url IS the shared stand-in
        // (modeBBuilder), so the full-context boot doubles as the never-hit pin's wiring-level twin —
        // a re-introduced startup fetch (any bean, any wiring step) moves the counter and fails here.
        int discoveryHitsBefore = OidcDiscoveryStandIn.discoveryHits();
        try (ConfigurableApplicationContext ctx = modeBBuilder(dir).run(minimalMemory(port))) {
            relay = ctx.getBean(RelayServerLifecycle.class);
            assertThat(relay.isRunning()).as("the relay acceptor lifecycle must be running").isTrue();
            group = ctx.getBean(EventLoopGroup.class);

            // The acceptor is really listening: the Socket ctor THROWS unless the connect completes —
            // that throw IS the probe (no accessor assert: isConnected() is only ever true post-ctor).
            try (Socket esme = new Socket(InetAddress.getLoopbackAddress(), port)) {
                // connected — the ctor is the assertion
            }

            // AD-1: the relay's loops are NAMED PLATFORM threads — a virtual thread never carries the
            // data-plane relay. (Named factory => observable here without reaching into Netty.)
            Set<Thread> relayThreads = Thread.getAllStackTraces().keySet().stream()
                    .filter(t -> t.getName().startsWith("companion-relay"))
                    .collect(Collectors.toSet());
            assertThat(relayThreads).as("the shared event loop must be running named threads").isNotEmpty();
            assertThat(relayThreads).as("AD-1: no virtual thread on the relay data plane")
                    .noneMatch(Thread::isVirtual);
            assertThat(OidcDiscoveryStandIn.discoveryHits())
                    .as("T9 at the BOOT boundary: a full reverse-cell context makes NO provider-metadata "
                            + "wire call — the never-hit pin extended from the adapter to the wiring")
                    .isEqualTo(discoveryHitsBefore);
        }
        assertThat(OidcDiscoveryStandIn.discoveryHits())
                .as("context close makes no provider call either (the full lifecycle, T9 boot boundary)")
                .isEqualTo(discoveryHitsBefore);
        // Context close ran stop(Runnable): acceptor closed BEFORE close returned. Neuter-guard:
        // running flips ONLY inside stop() — the group bean's destroyMethod releases the port and
        // flips isShutdown() on its own, so the group/port checks alone would stay GREEN under an
        // EMPTIED stop() body; this assert is the one that bites.
        assertThat(relay.isRunning())
                .as("context close must have run stop() — running flips only there")
                .isFalse();
        // 4.2 T2: stop() itself no longer quiesces the loop (the coordinator, 4.2 T3, owns that) —
        // so the quiesce pin asserts the FULL-APP close instead: by the time close() returns, the
        // group bean's destroyMethod backstop (destroyBeans runs inside close) has fired. Until T3
        // lands this backstop IS the loop's death; after T3 it re-fires as a no-op after the
        // coordinator — either way the loop is provably down once the context is gone.
        assertThat(group.isShutdown())
                .as("the full-app close must leave the shared event loop quiesced "
                        + "(the destroyMethod backstop until the 4.2 T3 coordinator's explicit-args quiesce)")
                .isTrue();
        // The port is released: a rebind MUST become possible once the full close is done (no new
        // binds — AD-22 step 1). Netty 4.2 completes the acceptor's close future before the OS
        // releases the listen socket (the ~ms trailing teardown this suite's probes POLL through —
        // see stopInvokesCallbackAndReleasesPort), and this row's acceptor also SERVED a connection
        // (the loopback probe), whose TIME_WAIT the probe's SO_REUSEADDR legitimately bypasses.
        assertThat(awaitRebindable(port))
                .as("the full-app close releases the acceptor port (the listener is gone)")
                .isTrue();
    }

    @Test
    @DisplayName("forward.mode-a cell: the acceptor is LIVE on its trusted leg ([B] flip — was the 2.2 inert pin)")
    void forwardCellBindsItsTrustedLegListener(@TempDir Path dir) throws IOException {
        // Story 3.3 flipped the 2.2 pin: under [B] EVERY cell listens — the forward's TRUSTED leg
        // (plaintext; no SslHandler on it — the TLS lives on the per-session DIALS, not this listener).
        int port = RelayTestFixtures.freePort();
        try (ConfigurableApplicationContext ctx = forwardABuilder(dir).run(minimalMemory(port))) {
            assertThat(ctx.getBean(RelayServerLifecycle.class).isRunning())
                    .as("[B]: the forward acceptor is live (the inert-boot pin of 2.2 is retired)")
                    .isTrue();
            // The listener is really there: the Socket ctor THROWS unless the connect completes.
            try (Socket esme = new Socket(InetAddress.getLoopbackAddress(), port)) {
                // connected — the ctor is the assertion
            }
        }
    }

    @Test
    @DisplayName("reverse.mode-a/c cells: the acceptor is LIVE with an internet-leg TLS listener (wiring)")
    void reverseTlsCellsBindTheirInternetLegListener(@TempDir Path dir) throws IOException {
        for (String mode : new String[] {"mode-a", "mode-c"}) {
            int port = RelayTestFixtures.freePort();
            try (ConfigurableApplicationContext ctx = reverseTlsBuilder(dir, mode).run(minimalMemory(port))) {
                assertThat(ctx.getBean(RelayServerLifecycle.class).isRunning())
                        .as("[" + mode + "] the reverse internet-leg TLS listener is live")
                        .isTrue();
                // The listener is really there (the Socket ctor THROWS unless the connect completes).
                // The TLS handshake semantics (one-way completes; REQUIRE refuses the cert-less peer)
                // are the e2e suite's pins — here the acceptor's liveness on the TLS cells is the
                // wiring proof.
                try (Socket esme = new Socket(InetAddress.getLoopbackAddress(), port)) {
                    // connected — the ctor is the assertion
                }
            }
        }
    }

    @Test
    @DisplayName("occupied port: start() throws BindException through refresh (AD-17 fail-fast, sync bind)")
    void bindFailureFailsStartupFailFast() throws IOException {
        int port = RelayTestFixtures.freePort();
        EventLoopGroup group = newGroup();
        RelayServerLifecycle lifecycle =
                new RelayServerLifecycle(RelayTestFixtures.modeBProperties(port, 1), group, newOptions(port),
                        RelayTestFixtures.modeBIngressInitializer(port));
        try (ServerSocket occupied = new ServerSocket(port)) {
            try {
                assertThatThrownBy(lifecycle::start)
                        .as("an occupied port must fail start() — never a silently-unbound acceptor "
                                + "(bind is SYNC; AD-17 fail-fast)")
                        .isInstanceOf(BindException.class);
                assertThat(lifecycle.isRunning()).isFalse();
            } finally {
                // The bind attempt started a loop thread even though it failed — the group is OURS to
                // release (lifecycle.stop() early-returns on the never-started lifecycle).
                group.shutdownGracefully().syncUninterruptibly();
            }
        }
    }

    @Test
    @DisplayName("stop(Runnable) invokes the callback, releases the port, and leaves the loop ALIVE (4.2 T2)")
    void stopInvokesCallbackAndReleasesPort() throws IOException {
        int port = RelayTestFixtures.freePort();
        EventLoopGroup group = newGroup();
        RelayServerLifecycle lifecycle =
                new RelayServerLifecycle(RelayTestFixtures.modeBProperties(port, 1), group, newOptions(port),
                        RelayTestFixtures.modeBIngressInitializer(port));
        try {
            lifecycle.start();
            assertThat(lifecycle.isRunning()).isTrue();

            AtomicBoolean callbackRan = new AtomicBoolean(false);
            lifecycle.stop(() -> callbackRan.set(true));
            assertThat(callbackRan)
                    .as("stop(Runnable) MUST invoke the callback (finally — releases the shutdown latch "
                            + "within the per-phase graceful window)")
                    .isTrue();
            assertThat(lifecycle.isRunning()).isFalse();
            // Port released: a plain rebind MUST become possible once the acceptor is gone. Netty
            // 4.2 completes the close FUTURE before the OS releases the listen socket (empirically
            // probed: 20/30 immediate rebinds refuse, 0/30 after 50ms — the trailing ~ms teardown,
            // NOT a TIME_WAIT; SO_REUSEADDR cannot help against a live mid-teardown socket), so the
            // probe POLLS briefly instead of racing the teardown. A port genuinely still held never
            // becomes bindable and fails here.
            assertThat(awaitRebindable(port))
                    .as("stop() releases the acceptor port (the listener is gone)")
                    .isTrue();
            lifecycle.stop(); // idempotent second stop: a no-op, never a throw
            // 4.2 T2 neuter-guard: stop() is acceptor-close ONLY — the loop must SURVIVE both stops
            // (the deny continuations execute on it; the quiesce is the 4.2 T3 coordinator's). A
            // re-added shutdownGracefully in stop() goes RED here. The FLAG is load-bearing
            // (empirically probed on Netty 4.2.16): isShuttingDown() flips IMMEDIATELY on the
            // caller's thread (live or lazy loop alike), while isShutdown()/isTerminated() only
            // flip at actual termination (~the 2s default quiet period after the quiesce began)
            // and even accept tasks meanwhile — an isShutdown()-based guard loses the race against
            // an async quiesce and stays GREEN under exactly the neutering it guards.
            assertThat(group.isShuttingDown())
                    .as("stop() must NOT quiesce the shared event loop (4.2 T2 — acceptor close only)")
                    .isFalse();
        } finally {
            // Exception-safety: a failed assertion must not strand the acceptor, the port, or the group
            // (stop() no longer quiesces the loop — the group is this test's OWN to release, 4.2 T2).
            lifecycle.stop();
            group.shutdownGracefully().syncUninterruptibly();
        }
    }

    @Test
    @DisplayName("phases: both lifecycles are explicit, and the acceptor STOPS first (AD-22 step 1)")
    void relayAcceptorStopsBeforeTheAppLifecycle() {
        // Exact pins (a neutered getPhase falls back to the implicit default and goes RED here), plus
        // the load-bearing ORDER: Spring stops higher phases first, so the acceptor must out-phase the
        // app lifecycle — the AD-22 shutdown coordinator (4.2 T3), whose walk runs after the data
        // plane is down and the deny window has fired. Constructed with the stand-in verifier + a
        // scratch group (never walked): the phase pin needs no live walk.
        assertThat(new RelayServerLifecycle(
                RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1), newGroup(),
                newOptions(RelayTestFixtures.freePort()), RelayTestFixtures.modeBIngressInitializer(RelayTestFixtures.freePort()))
                .getPhase())
                .isEqualTo(RelayServerLifecycle.RELAY_ACCEPTOR_PHASE);
        assertThat(new ProxyCompanionLifecycle(new AlwaysAllowBindCredentialVerifier(), newGroup()).getPhase())
                .isEqualTo(ProxyCompanionLifecycle.APP_PHASE);
        assertThat(RelayServerLifecycle.RELAY_ACCEPTOR_PHASE)
                .as("AD-22 step 1: the acceptor must stop BEFORE ProxyCompanionLifecycle "
                        + "(higher phase stops first)")
                .isGreaterThan(ProxyCompanionLifecycle.APP_PHASE);
    }

    // --- fixtures ---------------------------------------------------------------------------

    /**
     * Minimal AD-30 budget (the self-check is unconditional — every full boot carries it; T5b) plus
     * the ephemeral bind port, all as run-args (HIGHEST precedence: they must beat application.yml's
     * realistic memory defaults and its shipped bind.port).
     */
    private static String[] minimalMemory(int port) {
        return new String[] {
                "--companion.memory.max-inbound-depth=1",
                "--companion.memory.concurrent-pairs=1",
                "--companion.memory.safety-factor=1.0",
                "--companion.bind.port=" + port,
                // Story 4.1 T2: these yml-loading full boots otherwise bind yml's shipped metrics 9090
                // (the metrics endpoint lifecycle) — a free ephemeral port keeps them deterministic
                // against a locally-running Prometheus (run-args outrank yml; .properties() does not).
                "--companion.metrics.port=" + RelayTestFixtures.freePort()};
    }

    /**
     * A reverse.mode-b boot builder (the branch is supplied as default properties — yml has it
     * commented out, so these are the only source — T5 pattern). Story 3.2 (AD-12 amended
     * 2026-08-18): reverse cells adjudicate — the oidc node is REQUIRED here too (stand-in
     * provider-url + fixture-CA IdP trust store + the three budget keys at the yml-template defaults).
     */
    private static SpringApplicationBuilder modeBBuilder(Path dir) throws IOException {
        // NON-BLANK content (3.2 T7): this full boot constructs the ROPC adapter bean, which loads the
        // secret at startup — an empty file would refuse (SEC-060).
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "stand-in-client-secret\n");
        Path idpTrustStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        return new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "companion.reverse.mode-b.smsc.host=smsc.example",
                        "companion.reverse.mode-b.smsc.port=2775",
                        "companion.reverse.mode-b.acknowledged=true",
                        "companion.reverse.mode-b.oidc.provider-url=" + OidcDiscoveryStandIn.url(),
                        "companion.reverse.mode-b.oidc.client-id=smpp-client-confidential",
                        "companion.reverse.mode-b.oidc.client-secret-path=" + secret,
                        "companion.reverse.mode-b.oidc.trust-store.path=" + idpTrustStore,
                        "companion.reverse.mode-b.oidc.trust-store.password=" + RelayTestFixtures.IDP_STORE_PASSWORD,
                        "companion.reverse.mode-b.oidc.timeout=4s",
                        "companion.reverse.mode-b.oidc.max-in-flight=64");
    }

    /**
     * A forward.mode-a boot builder (mirrors BootstrapLifecycleTest.builder): the [B] DIAL material
     * (the committed SMPP-leg trust store — the full boot constructs SmppLegTlsFactory). NO oidc keys
     * — the forward role is a trusted-side relay (AD-12 amended 2026-08-18); the reverse adjudicates.
     */
    private static SpringApplicationBuilder forwardABuilder(Path dir) throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        return new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "companion.forward.mode-a.trust-store.path=" + legs.trustStore(),
                        "companion.forward.mode-a.trust-store.password=" + RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD,
                        "companion.forward.mode-a.routing[0].system-id=carrierOne",
                        "companion.forward.mode-a.routing[0].host=reverse.internal",
                        "companion.forward.mode-a.routing[0].port=2776");
    }

    /**
     * A reverse.mode-a/mode-c boot builder (the internet-leg TLS listener cells): the committed
     * server cert+key (+ the REQUIRE-side trust store in mode-c) + the T2 oidc stand-in keys.
     */
    private static SpringApplicationBuilder reverseTlsBuilder(Path dir, String mode) throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "stand-in-client-secret\n");
        Path idpTrustStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        String b = "companion.reverse." + mode;
        SpringApplicationBuilder builder = new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        b + ".smsc.host=smsc.example",
                        b + ".smsc.port=2775",
                        b + ".server-cert.cert-path=" + legs.reverseServerCert(),
                        b + ".server-cert.key-path=" + legs.reverseServerKey(),
                        b + ".oidc.provider-url=" + OidcDiscoveryStandIn.url(),
                        b + ".oidc.client-id=smpp-client-confidential",
                        b + ".oidc.client-secret-path=" + secret,
                        b + ".oidc.trust-store.path=" + idpTrustStore,
                        b + ".oidc.trust-store.password=" + RelayTestFixtures.IDP_STORE_PASSWORD,
                        b + ".oidc.timeout=4s",
                        b + ".oidc.max-in-flight=64");
        if ("mode-c".equals(mode)) {
            builder.properties(
                    b + ".trust-store.path=" + legs.trustStore(),
                    b + ".trust-store.password=" + RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD);
        }
        return builder;
    }

    private static RelayChannelOptions newOptions(int port) {
        return new RelayChannelOptions(RelayTestFixtures.modeBProperties(port, 1), PooledByteBufAllocator.DEFAULT);
    }

    /**
     * Polls (25ms interval, 2s cap) until {@code port} is bindable by a LISTENER — the acceptor
     * port-reclaim probe. Netty 4.2 completes the channel-close FUTURE before the OS releases the
     * listen socket (empirically probed on 4.2.16: an immediate rebind refuses ~2/3 of the time
     * and 0/30 after a 50ms settle — the trailing teardown, which SO_REUSEADDR cannot bypass
     * because the conflicting socket is still live), so a one-shot probe races a ~ms window this
     * poll rides out instead. A port genuinely still held (a surviving acceptor) never becomes
     * bindable and this returns {@code false}. The probe itself is the shared
     * {@link RelayTestFixtures#rebindableProbe(int)} (SO_REUSEADDR armed BEFORE the bind — a
     * TIME_WAIT left by a served connection must not fail the pin).
     */
    private static boolean awaitRebindable(int port) {
        long deadline = System.currentTimeMillis() + 2_000;
        while (System.currentTimeMillis() < deadline) {
            try (ServerSocket ignored = RelayTestFixtures.rebindableProbe(port)) {
                return true;
            } catch (IOException e) {
                try {
                    Thread.sleep(25);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return false;
    }

    /** Mirrors the RelayNettyConfig bean: the Netty 4.2 NIO idiom (NOT the deprecated NioEventLoopGroup). */
    private static EventLoopGroup newGroup() {
        return new MultiThreadIoEventLoopGroup(
                1, new DefaultThreadFactory("relay-lifecycle-test"), NioIoHandler.newFactory());
    }
}
