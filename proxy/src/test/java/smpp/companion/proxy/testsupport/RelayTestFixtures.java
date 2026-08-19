package smpp.companion.proxy.testsupport;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.List;

import io.netty.buffer.PooledByteBufAllocator;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.observability.CapturingSpliceObserver;
import smpp.companion.proxy.observability.NoopSpliceObserver;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.relay.netty.RelayIngressInitializer;
import smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier;

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
                OidcDiscoveryStandIn.url(), "smpp-client-confidential",
                "/run/secrets/oidc-client-secret",
                new ProxyCompanionProperties.TrustStore("/run/secrets/idp-truststore.p12", null),
                Duration.ofSeconds(4), 64, Duration.ofMinutes(5));
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
                new ProxyCompanionProperties.Bind(bindPort, DEFAULT_ADJUDICATION_DEADLINE),
                new ProxyCompanionProperties.Memory(
                        maxInboundDepth, 1, 1.0, ProxyCompanionProperties.Memory.BudgetCheck.FAIL),
                new ProxyCompanionProperties.Tls(List.of("TLSv1.3"), List.of(), List.of()),
                null,
                new ProxyCompanionProperties.Reverse(
                        null,
                        new ProxyCompanionProperties.ReverseModeB(
                                new ProxyCompanionProperties.Smsc(smscHost, smscPort), true, testOidc()),
                        null));
    }

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
        ProxyCompanionProperties properties = modeBProperties(bindPort, 1);
        ConnectionRegistry registry = new ConnectionRegistry();
        NoopSpliceObserver observer = new NoopSpliceObserver();
        return new RelayIngressInitializer(
                new AlwaysAllowBindCredentialVerifier(),
                registry,
                observer,
                properties,
                new RelayEgressInitializer(registry, observer),
                new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT));
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
        ConnectionRegistry registry = new ConnectionRegistry();
        CapturingSpliceObserver observer = new CapturingSpliceObserver();
        return new ModeBRelayHarness(
                properties,
                new RelayIngressInitializer(
                        new AlwaysAllowBindCredentialVerifier(),
                        registry,
                        observer,
                        properties,
                        new RelayEgressInitializer(registry, observer),
                        new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT)),
                registry,
                observer);
    }

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
