package smpp.companion.proxy.testsupport;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.List;

import io.netty.buffer.PooledByteBufAllocator;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.observability.CapturingSpliceObserver;
import smpp.companion.proxy.observability.NoopSpliceObserver;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.relay.netty.RelayIngressInitializer;
import smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.tls.SmppLegTlsFactory;

/**
 * Shared relay-test fixtures (T6 code-review consolidation): the free-ephemeral-port probe and the
 * minimal valid reverse.mode-b {@link ProxyCompanionProperties} record used by direct-construction
 * tests. One home so a {@code ProxyCompanionProperties} field addition breaks ONE fixture instead of
 * scattered near-copies drifting apart.
 */
public final class RelayTestFixtures {

    private RelayTestFixtures() {}

    /**
     * The documented application.yml default for {@code companion.bind.adjudication-deadline} — shared by
     * the direct-construction fixtures so they stay uniform with real boots (Story 2.2 T7 owner FIXME).
     */
    public static final Duration DEFAULT_ADJUDICATION_DEADLINE = Duration.ofSeconds(4);

    /**
     * PKCS12 password of the Keycloak fixture's {@code truststore.p12} / {@code client-keystore.p12}
     * ({@code keycloak/certs/} — see {@code KeycloakFixture.STORE_PASSWORD}; restated here because
     * that constant is package-private to {@code security/}). NOT a production secret.
     */
    public static final String IDP_STORE_PASSWORD = "smpp-test";

    /**
     * A minimal VALID {@link ProxyCompanionProperties.Oidc} for direct-construction test fixtures
     * (Story 3.2; the oidc node lives on the REVERSE cells per the AD-12 amendment of 2026-08-18).
     * Stand-in provider-url; dummy paths — these fixtures feed relay-level tests that never run the
     * config validator, so the files need not exist. Budget values are the yml-template defaults.
     */
    public static ProxyCompanionProperties.Oidc testOidc() {
        return new ProxyCompanionProperties.Oidc(
                URI.create(OidcDiscoveryStandIn.url()), "smpp-client-confidential",
                "/run/secrets/oidc-client-secret",
                new ProxyCompanionProperties.TrustStore("/run/secrets/idp-truststore.p12", null),
                Duration.ofSeconds(4), 64);
    }

    /**
     * Copies the Keycloak fixture's IdP trust store ({@code keycloak/certs/truststore.p12}, the
     * minimal single-CA anchor — AD-13, never JDK cacerts) to {@code target} and returns it: the
     * {@code companion.reverse.mode-*.oidc.trust-store.path} fixture for reverse-cell configs
     * (Story 3.2 T1). Anchoring the fixture CA — rather than a random generated cert — is what lets
     * the same config keep passing from T2 on, when the adapter's discovery/SSLContext build actually
     * handshakes with the shared {@link OidcDiscoveryStandIn} (its server cert chains to that CA).
     */
    public static Path idpTrustStoreFixture(Path target) {
        try (InputStream in = RelayTestFixtures.class.getResourceAsStream("/keycloak/certs/truststore.p12")) {
            if (in == null) {
                throw new IllegalStateException("fixture resource missing: /keycloak/certs/truststore.p12");
            }
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
            return target;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Probes a free ephemeral port (bound then immediately released). Probe-then-use carries an
     * inherent TOCTOU window — accepted test practice (T6 review): each caller re-binds the port as a
     * run-arg / acceptor bind immediately after probing.
     */
    public static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * A minimal VALID reverse.mode-b properties record (the relay cell): the given acceptor bind port
     * and AD-30 {@code max-inbound-depth}; everything else minimal (concurrent-pairs 1, safety-factor
     * 1.0, budget-check FAIL — the smallest legal AD-30 budget), TLS lists inert (a plaintext slice
     * consumes no TLS settings), no forward branch.
     */
    public static ProxyCompanionProperties modeBProperties(int bindPort, int maxInboundDepth) {
        return modeBProperties(bindPort, maxInboundDepth, "smsc.example", 2775);
    }

    /**
     * The egress-targeted variant the T9/T10 socket-level smoke tests use: the single
     * {@code companion.reverse.mode-b.smsc} points at the caller's in-JVM mock (loopback host + the
     * mock's ephemeral port) instead of the unreachable {@code smsc.example} placeholder.
     */
    public static ProxyCompanionProperties modeBProperties(
            int bindPort, int maxInboundDepth, String smscHost, int smscPort) {
        return new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(
                        bindPort, DEFAULT_BIND_HOST, DEFAULT_ADJUDICATION_DEADLINE),
                new ProxyCompanionProperties.Memory(
                        maxInboundDepth, DEFAULT_CONCURRENT_PAIRS, 1.0,
                        ProxyCompanionProperties.Memory.BudgetCheck.FAIL),
                new ProxyCompanionProperties.Tls(List.of("TLSv1.3"), List.of(), List.of()),
                null,
                new ProxyCompanionProperties.Reverse(
                        null,
                        new ProxyCompanionProperties.ReverseModeB(
                                new ProxyCompanionProperties.Smsc(smscHost, smscPort), true, testOidc()),
                        null));
    }

    /**
     * The loopback listener host every direct-construction fixture binds (Story 3.3 / F13: the
     * listener now binds host:port, and every fixture consumer connects via the loopback address).
     */
    public static final String DEFAULT_BIND_HOST = "127.0.0.1";

    /**
     * The realistic AD-34 TLS lists the TLS-bearing cells need (the fixture certs are RSA, and the
     * 1.2 set carries the ECDHE_RSA suites that intersect — the minimal {@code List.of()} framer-only
     * lists of the plaintext cells would refuse inside {@link SmppLegTlsFactory}).
     */
    public static final List<String> TLS_PROTOCOLS = List.of("TLSv1.3", "TLSv1.2");
    public static final List<String> TLS12_SUITES = List.of(
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    public static final List<String> TLS13_SUITES = List.of(
            "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256");

    /**
     * The Story 3.3 SMPP-leg test PKI ({@code keycloak/certs/smpp-*}, committed; see its
     * {@code generate.sh}) materialized into {@code dir}: the reverse's internet-leg server
     * cert+key, the forward's per-instance client cert+key, the CA-only trust store anchoring
     * both directions, and the FOREIGN-CA client pair (the AC4 "unanchored" negative arm —
     * presented but not chained to the anchor). One copy per temp dir; TLS material is immutable (AD-18).
     */
    public static SmppTlsLegs smppTlsLegs(Path dir) {
        return new SmppTlsLegs(
                copyResource("/keycloak/certs/smpp-reverse-server.pem", dir.resolve("smpp-reverse-server.pem")),
                copyResource("/keycloak/certs/smpp-reverse-server-key.pem", dir.resolve("smpp-reverse-server-key.pem")),
                copyResource("/keycloak/certs/smpp-forward-client.pem", dir.resolve("smpp-forward-client.pem")),
                copyResource("/keycloak/certs/smpp-forward-client-key.pem", dir.resolve("smpp-forward-client-key.pem")),
                copyResource("/keycloak/certs/smpp-truststore.p12", dir.resolve("smpp-truststore.p12")),
                copyResource("/keycloak/certs/smpp-foreign-client.pem", dir.resolve("smpp-foreign-client.pem")),
                copyResource("/keycloak/certs/smpp-foreign-client-key.pem", dir.resolve("smpp-foreign-client-key.pem")));
    }

    /** The materialized SMPP-leg fixture files (see {@link #smppTlsLegs(Path)}). */
    public record SmppTlsLegs(
            Path reverseServerCert, Path reverseServerKey,
            Path forwardClientCert, Path forwardClientKey,
            Path trustStore,
            Path foreignClientCert, Path foreignClientKey) {

        /** The store password of the committed fixture PKI ({@code generate.sh} PASS). */
        public static final String STORE_PASSWORD = "smpp-test";

        /** The fixture trust-store record ({@code TrustStore(path, password)}). */
        public ProxyCompanionProperties.TrustStore trustStoreRecord() {
            return new ProxyCompanionProperties.TrustStore(trustStore.toString(), STORE_PASSWORD);
        }
    }

    /** Copies a classpath resource to {@code target} (REPLACE_EXISTING) and returns it. */
    public static Path copyResource(String resource, Path target) {
        try (InputStream in = RelayTestFixtures.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("fixture resource missing: " + resource);
            }
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
            return target;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // --- Story 3.3 cell fixtures ([B] topology): minimal VALID properties per TLS-bearing cell ------

    /**
     * forward &times; A: trusted-leg listener (plaintext) + per-session one-way TLS dial — trust
     * store + routing to the caller's reverse target. AlwaysAllow-verifier cell (AD-12 amended).
     */
    public static ProxyCompanionProperties forwardAProperties(
            int bindPort, int concurrentPairs, SmppTlsLegs legs, String reverseHost, int reversePort) {
        return new ProxyCompanionProperties(
                baseBind(bindPort),
                baseMemory(concurrentPairs),
                new ProxyCompanionProperties.Tls(TLS_PROTOCOLS, TLS12_SUITES, TLS13_SUITES),
                new ProxyCompanionProperties.Forward(
                        new ProxyCompanionProperties.ForwardModeA(
                                legs.trustStoreRecord(),
                                List.of(new ProxyCompanionProperties.RoutingEntry(
                                        "carrierOne", reverseHost, reversePort, null))),
                        null, null),
                null);
    }

    /**
     * forward &times; C: forward-A material + the per-instance client cert+key presented on every dial.
     */
    public static ProxyCompanionProperties forwardCProperties(
            int bindPort, int concurrentPairs, SmppTlsLegs legs, String reverseHost, int reversePort) {
        return new ProxyCompanionProperties(
                baseBind(bindPort),
                baseMemory(concurrentPairs),
                new ProxyCompanionProperties.Tls(TLS_PROTOCOLS, TLS12_SUITES, TLS13_SUITES),
                new ProxyCompanionProperties.Forward(
                        null,
                        new ProxyCompanionProperties.ForwardModeC(
                                new ProxyCompanionProperties.ClientCert(
                                        legs.forwardClientCert().toString(), legs.forwardClientKey().toString()),
                                legs.trustStoreRecord(),
                                List.of(new ProxyCompanionProperties.RoutingEntry(
                                        "carrierOne", reverseHost, reversePort, null))),
                        null),
                null);
    }

    /** reverse &times; A: internet-leg TLS listener (server cert) + plaintext SMSC dial + OIDC. */
    public static ProxyCompanionProperties reverseAProperties(
            int bindPort, int concurrentPairs, SmppTlsLegs legs, String smscHost, int smscPort) {
        return new ProxyCompanionProperties(
                baseBind(bindPort),
                baseMemory(concurrentPairs),
                new ProxyCompanionProperties.Tls(TLS_PROTOCOLS, TLS12_SUITES, TLS13_SUITES),
                null,
                new ProxyCompanionProperties.Reverse(
                        new ProxyCompanionProperties.ReverseModeA(
                                new ProxyCompanionProperties.Smsc(smscHost, smscPort),
                                new ProxyCompanionProperties.ServerCert(
                                        legs.reverseServerCert().toString(), legs.reverseServerKey().toString()),
                                testOidc()),
                        null, null));
    }

    /** reverse &times; C: the reverse-A listener + trust store REQUIRE-validating the forward's client cert. */
    public static ProxyCompanionProperties reverseCProperties(
            int bindPort, int concurrentPairs, SmppTlsLegs legs, String smscHost, int smscPort) {
        return new ProxyCompanionProperties(
                baseBind(bindPort),
                baseMemory(concurrentPairs),
                new ProxyCompanionProperties.Tls(TLS_PROTOCOLS, TLS12_SUITES, TLS13_SUITES),
                null,
                new ProxyCompanionProperties.Reverse(
                        null, null,
                        new ProxyCompanionProperties.ReverseModeC(
                                new ProxyCompanionProperties.Smsc(smscHost, smscPort),
                                new ProxyCompanionProperties.ServerCert(
                                        legs.reverseServerCert().toString(), legs.reverseServerKey().toString()),
                                legs.trustStoreRecord(),
                                testOidc())));
    }

    private static ProxyCompanionProperties.Bind baseBind(int bindPort) {
        return new ProxyCompanionProperties.Bind(
                bindPort, DEFAULT_BIND_HOST, DEFAULT_ADJUDICATION_DEADLINE);
    }

    private static ProxyCompanionProperties.Memory baseMemory() {
        return baseMemory(1);
    }

    /** The AD-30 budget whose concurrent-pairs input ALSO carries the F13 acceptor cap (one number). */
    private static ProxyCompanionProperties.Memory baseMemory(int concurrentPairs) {
        return new ProxyCompanionProperties.Memory(
                1, concurrentPairs, 1.0, ProxyCompanionProperties.Memory.BudgetCheck.FAIL);
    }

    /**
     * The concurrent-pairs budget input every direct-construction mode-b fixture carries — which,
     * since the Story 3.3 review rework, is ALSO the F13 acceptor cap (one number). Generous so the
     * N-concurrent-binds smoke tests never hit it; the AD-30 self-check is a BIND-time check these
     * directly-constructed records never run.
     */
    public static final int DEFAULT_CONCURRENT_PAIRS = 64;

    /**
     * The real production ingress wiring for direct-construction tests (T7 made the initializer
     * constructor-carrying; T8 made the egress initializer constructor-carrying too): the default
     * verifier/observer/registry beans, the mode-b properties, the egress initializer, and the shared
     * substrate options. The registry/observer instances are SHARED between the two initializers —
     * Spring wires the same singleton beans into both, and the egress-leg RelayHandler (the AD-25
     * flipper) must resolve the same registry the ingress interceptor wrote. One home for the same
     * drift reason as {@link #modeBProperties} — a constructor-signature change breaks ONE fixture.
     */
    public static RelayIngressInitializer modeBIngressInitializer(int bindPort) {
        return modeBRelayHarness(modeBProperties(bindPort, 1)).ingressInitializer();
    }

    /**
     * The real production wiring for the T9/T10 socket-level smoke tests: same constructor graph as
     * {@link #modeBIngressInitializer(int)} (the real initializers + the production default
     * {@code AlwaysAllow} verifier + the shared substrate options) but with (a) the egress target
     * pointed at the caller's in-JVM mock and (b) a {@link CapturingSpliceObserver} whose handle the
     * test keeps — so a smoke test can assert the pinned triggers while driving REAL TCP sockets
     * through the REAL acceptor ({@code RelayServerLifecycle.start()}; the T6-review deferred
     * wiring-pin — real PDUs through the acceptor bite on any dropped wiring line).
     *
     * @param properties the egress-targeted mode-b record (see
     *         {@link #modeBProperties(int, int, String, int)}) — the SAME instance the initializer
     *         graph receives, so the harness caller's {@code RelayServerLifecycle} binds the port the
     *         record carries.
     */
    public static ModeBRelayHarness modeBRelayHarness(ProxyCompanionProperties properties) {
        RelayHarness harness = relayHarness(properties, new AlwaysAllowBindCredentialVerifier());
        return new ModeBRelayHarness(
                properties,
                harness.ingressInitializer(),
                harness.registry(),
                harness.observer());
    }

    /**
     * The generic Story 3.3 harness: the REAL production wiring graph for ANY cell's properties —
     * the shared registry/observer, the plain and TLS-carrying initializers behind the cell's
     * {@link SmppLegTlsFactory}, and the routing table. The TLS factory's delegated-task executor is
     * the same-thread direct executor (handshake crypto on the calling thread — the AD-28 bounded
     * pool is a production bean; tests do not saturate).
     *
     * @param properties the cell's properties record; the SAME instance the graph receives.
     * @param verifier the cell's verifier (forward cells: AlwaysAllow; reverse: the caller's choice).
     */
    public static RelayHarness relayHarness(ProxyCompanionProperties properties, BindCredentialVerifier verifier) {
        return relayHarness(properties, verifier, Runnable::run);
    }

    /**
     * The executor-parameterized variant ({@code relayHarness(properties, verifier)} delegates with
     * the same-thread direct executor). The AD-28 observation test (code review 2026-08-27) injects
     * a RECORDING executor here so delegated handshake tasks become visible — under the direct
     * executor they are indistinguishable from same-thread work.
     *
     * @param delegatedTaskExecutor rides every {@code SslHandler} the harness's factory builds
     *         (the production bean's bounded pool stands in for it).
     */
    public static RelayHarness relayHarness(
            ProxyCompanionProperties properties, BindCredentialVerifier verifier,
            java.util.concurrent.Executor delegatedTaskExecutor) {
        ConnectionRegistry registry = new ConnectionRegistry();
        CapturingSpliceObserver observer = new CapturingSpliceObserver();
        SmppLegTlsFactory tlsFactory = new SmppLegTlsFactory(properties, delegatedTaskExecutor);
        RelayEgressInitializer egress = new RelayEgressInitializer(registry, observer);
        RelayIngressInitializer ingress = new RelayIngressInitializer(
                verifier, registry, observer, properties, egress,
                new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                new RoutingTable(properties), tlsFactory);
        return new RelayHarness(properties, ingress, egress, registry, observer, tlsFactory);
    }

    /** The generic harness (see {@link #relayHarness(ProxyCompanionProperties, BindCredentialVerifier)}). */
    public record RelayHarness(
            ProxyCompanionProperties properties,
            RelayIngressInitializer ingressInitializer,
            RelayEgressInitializer egressInitializer,
            ConnectionRegistry registry,
            CapturingSpliceObserver observer,
            SmppLegTlsFactory tlsFactory) { }

    /**
     * The socket-smoke harness: the properties record, the real ingress initializer for
     * {@code RelayServerLifecycle}, and the SHARED registry/observer handles the initializers were
     * wired with (the same singleton wiring Spring does — the egress-leg flipper must resolve the
     * registry the ingress interceptor wrote).
     */
    public record ModeBRelayHarness(
            ProxyCompanionProperties properties,
            RelayIngressInitializer ingressInitializer,
            ConnectionRegistry registry,
            CapturingSpliceObserver observer) { }
}
