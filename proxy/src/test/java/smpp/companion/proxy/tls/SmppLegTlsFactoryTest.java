package smpp.companion.proxy.tls;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.netty.channel.embedded.EmbeddedChannel;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Story 3.3 T3 (unit) — the SMPP-leg TLS factory's per-cell construction matrix and its
 * fail-closed guards: the listener/egress split per cell, Mode C's REQUIRE (never WANT — AD-11),
 * the 5-state trust-store load (SEC-050/AD-13), unparseable cert/key refusal, the per-context AD-34
 * intersection (D2: empty on either axis refuses, for the listener AND each egress context), the
 * AD-20 IP-literal endpoint-identification rule, and the AD-29 {@code forward.tls-contexts} override
 * resolution (the SEC-098 dangling-id defensive re-check). Every fail-fast guard here gets a
 * RED-on-neuter mutation in the story's ledger (T8).
 *
 * <p>Handlers are exercised on {@link EmbeddedChannel}s (per-channel instances; the engine is
 * per-connection state). The delegated-task executor is the same-thread direct executor — the AD-28
 * bounded pool is a production bean and these tests never saturate.
 */
@Tag("unit")
@Tag("sec")
@Tag("p1")
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel.close() in test teardown is
// fire-and-forget — the close future can only fail on an already-finished test channel, and there is
// nothing to observe from it in a construction-matrix test.
class SmppLegTlsFactoryTest {

    /** The per-cell listener/egress split: which legs carry TLS on which cells. */
    @Test
    @DisplayName("per-cell split: reverse a/c = TLS listener + NO TLS egress; forward a/c = NO listener + TLS egress; b = none")
    void perCellListenerEgressSplit(@TempDir Path dir) {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);

        SmppLegTlsFactory reverseA =
                new SmppLegTlsFactory(RelayTestFixtures.reverseAProperties(0, 8, legs, "smsc.example", 2775),
                        Runnable::run);
        assertThat(reverseA.listenerTls()).as("reverse.mode-a holds the internet-leg TLS listener").isTrue();
        assertThat(reverseA.egressTls()).as("the SMSC leg is plaintext in every mode (AD-12 amended)").isFalse();

        SmppLegTlsFactory reverseC =
                new SmppLegTlsFactory(RelayTestFixtures.reverseCProperties(0, 8, legs, "smsc.example", 2775),
                        Runnable::run);
        assertThat(reverseC.listenerTls()).isTrue();
        assertThat(reverseC.egressTls()).isFalse();

        SmppLegTlsFactory forwardA =
                new SmppLegTlsFactory(RelayTestFixtures.forwardAProperties(0, 8, legs, "127.0.0.1", 2776),
                        Runnable::run);
        assertThat(forwardA.listenerTls()).as("the forward's trusted leg is plaintext (AD-15)").isFalse();
        assertThat(forwardA.egressTls()).as("the forward dials TLS per session ([B])").isTrue();

        SmppLegTlsFactory modeB =
                new SmppLegTlsFactory(RelayTestFixtures.modeBProperties(0, 1), Runnable::run);
        assertThat(modeB.listenerTls()).as("reverse.mode-b is plaintext end to end (byte-identical to 2.2)").isFalse();
        assertThat(modeB.egressTls()).isFalse();
    }

    /** AC3/AD-11: Mode C REQUIREs the client cert; Mode A never asks for one (one-way). */
    @Test
    @DisplayName("AD-11/AD-13: mode-c listener engine setWantClientAuth(true) [REQUIRE]; mode-a never asks")
    void modeCListenerRequiresClientAuthModeADoesNot(@TempDir Path dir) {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        javax.net.ssl.SSLEngine modeAEngine = listenerEngine(
                new SmppLegTlsFactory(RelayTestFixtures.reverseAProperties(0, 8, legs, "smsc.example", 2775), Runnable::run));
        javax.net.ssl.SSLEngine modeCEngine = listenerEngine(
                new SmppLegTlsFactory(RelayTestFixtures.reverseCProperties(0, 8, legs, "smsc.example", 2775), Runnable::run));
        assertThat(modeAEngine.getWantClientAuth())
                .as("one-way TLS presents a cert; it never requests one")
                .isFalse();
        assertThat(modeAEngine.getNeedClientAuth()).isFalse();
        assertThat(modeCEngine.getNeedClientAuth())
                .as("mode-c REQUIREs the forward's client cert — REQUIRE never WANT (AD-11/AD-13)")
                .isTrue();
    }

    /** The egress handler per routing entry: one per channel, engine carries the peer host/port. */
    @Test
    @DisplayName("forward egress: one client handler per dial, keyed by the routing entry's system_id")
    void forwardEgressHandlerPerRoutingEntry(@TempDir Path dir) {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        SmppLegTlsFactory factory = new SmppLegTlsFactory(
                RelayTestFixtures.forwardAProperties(0, 8, legs, "127.0.0.1", 2776), Runnable::run);
        ProxyCompanionProperties.RoutingEntry target = new ProxyCompanionProperties.RoutingEntry(
                "carrierOne", "127.0.0.1", 2776, null);
        EmbeddedChannel dialA = new EmbeddedChannel();
        EmbeddedChannel dialB = new EmbeddedChannel();
        try {
            var handlerA = factory.newEgressSslHandler(dialA.alloc(), target);
            var handlerB = factory.newEgressSslHandler(dialB.alloc(), target);
            assertThat(handlerA).as("every dial gets a FRESH handler (per-connection engine)").isNotSameAs(handlerB);
            // A system_id the factory did not index is a wiring bug — fail fast, never a silent dial.
            ProxyCompanionProperties.RoutingEntry unknown = new ProxyCompanionProperties.RoutingEntry(
                    "notInTheTable", "127.0.0.1", 2776, null);
            assertThatThrownBy(() -> factory.newEgressSslHandler(dialA.alloc(), unknown))
                    .as("an unindexed routing entry must fail fast")
                    .isInstanceOf(IllegalStateException.class);
        } finally {
            dialA.close();
            dialB.close();
        }
    }

    /** AC2/AD-13: any of the 5 trust-store states on the egress (dial) context refuses construction. */
    @Test
    @DisplayName("SEC-050: the 5-state trust-store matrix on the forward dial context -> refuse construction")
    void fiveStateTrustStoreMatrixRefuses(@TempDir Path dir) throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        Path ts = dir.resolve("mutated-truststore.p12");

        // state 1: absent — point at a path that does not exist.
        assertThatThrownBy(() -> forwardFactory(legs, dir.resolve("no-such-truststore.p12").toString(), "changeit"))
                .as("absent trust store must refuse")
                .hasMessageContaining("does not exist");

        // state 2: empty (zero bytes).
        Files.write(ts, new byte[0]);
        assertThatThrownBy(() -> forwardFactory(legs, ts.toString(), "changeit"))
                .as("empty trust store must refuse")
                .hasMessageContaining("empty");

        // state 3: wrong format.
        Files.write(ts, "this is not a keystore".getBytes());
        assertThatThrownBy(() -> forwardFactory(legs, ts.toString(), "changeit"))
                .as("wrong-format trust store must refuse")
                .hasMessageContaining("not a valid trust store");

        // state 4: wrong password (a REAL store, the wrong secret).
        assertThatThrownBy(() -> forwardFactory(legs, legs.trustStore().toString(), "wrong-password"))
                .as("wrong-password trust store must refuse")
                .hasMessageContaining("not a valid trust store");

        // state 5: zero trustedCertEntry (valid PKCS12, no anchors).
        try {
            java.security.KeyStore empty = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
            empty.load(null, "changeit".toCharArray());
            try (java.io.OutputStream out = Files.newOutputStream(ts)) {
                empty.store(out, "changeit".toCharArray());
            }
        } catch (Exception e) {
            throw new IllegalStateException("could not build the zero-entry fixture store", e);
        }
        assertThatThrownBy(() -> forwardFactory(legs, ts.toString(), "changeit"))
                .as("an anchor-less store would trust nothing — must refuse (never a cacerts fallback)")
                .hasMessageContaining("zero trustedCertEntry");
    }

    /** The listener material itself: unparseable/garbage cert or key refuses at construction. */
    @Test
    @DisplayName("SEC-056: an unparseable server cert/key on the reverse listener -> refuse construction")
    void garbageListenerMaterialRefuses(@TempDir Path dir) throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        Path garbageCert = dir.resolve("garbage.crt");
        Files.write(garbageCert, "not a pem".getBytes());
        ProxyCompanionProperties reverseA = new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(0, "127.0.0.1", RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE),
                new ProxyCompanionProperties.Memory(1, 1, 1.0, ProxyCompanionProperties.Memory.BudgetCheck.FAIL),
                new ProxyCompanionProperties.Tls(
                        RelayTestFixtures.TLS_PROTOCOLS, RelayTestFixtures.TLS12_SUITES,
                        RelayTestFixtures.TLS13_SUITES),
                null,
                new ProxyCompanionProperties.Reverse(
                        new ProxyCompanionProperties.ReverseModeA(
                                new ProxyCompanionProperties.Smsc("smsc.example", 2775),
                                new ProxyCompanionProperties.ServerCert(
                                        garbageCert.toString(), legs.reverseServerKey().toString()),
                                RelayTestFixtures.testOidc()),
                        null, null));
        assertThatThrownBy(() -> new SmppLegTlsFactory(reverseA, Runnable::run))
                .as("garbage listener material must refuse startup (fail-closed, AD-17)")
                .isInstanceOf(IllegalStateException.class);
    }

    /** AC2/AD-34 (D2): an empty intersection on EITHER axis refuses — for the listener AND each egress context. */
    @Test
    @DisplayName("AD-34: empty cipher/protocol intersection per context -> refuse (listener and egress alike)")
    void emptyIntersectionRefusesPerContext(@TempDir Path dir) {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);

        // (a) egress context with a non-intersecting cipher set.
        ProxyCompanionProperties badCiphers = withTls(RelayTestFixtures.forwardAProperties(0, 8, legs, "127.0.0.1", 2776),
                List.of("TLSv1.3", "TLSv1.2"), List.of("TLS_FAKE_NOT_A_SUITE"), List.of("TLS_FAKE13"));
        assertThatThrownBy(() -> new SmppLegTlsFactory(badCiphers, Runnable::run))
                .as("an empty cipher intersection on the egress context must refuse")
                .hasMessageContaining("empty intersection")
                .hasMessageContaining("AD-34");

        // (b) egress context with a non-intersecting protocol set.
        ProxyCompanionProperties badProtocols = withTls(RelayTestFixtures.forwardAProperties(0, 8, legs, "127.0.0.1", 2776),
                List.of("TLSv9.99"), RelayTestFixtures.TLS12_SUITES, RelayTestFixtures.TLS13_SUITES);
        assertThatThrownBy(() -> new SmppLegTlsFactory(badProtocols, Runnable::run))
                .as("an empty protocol intersection on the egress context must refuse")
                .hasMessageContaining("empty intersection")
                .hasMessageContaining("AD-34");

        // (c) the LISTENER context enforces the same per-context gate.
        ProxyCompanionProperties badListener = withTls(RelayTestFixtures.reverseAProperties(0, 8, legs, "smsc.example", 2775),
                List.of("TLSv1.3", "TLSv1.2"), List.of("TLS_FAKE_NOT_A_SUITE"), List.of("TLS_FAKE13"));
        assertThatThrownBy(() -> new SmppLegTlsFactory(badListener, Runnable::run))
                .as("an empty cipher intersection on the listener context must refuse")
                .hasMessageContaining("empty intersection");

        // (d) SEC-100/AD-34 APPLICABILITY (review 2026-08-27): TLS-1.3-only suites with
        // protocols=[TLSv1.2] — BOTH intersections non-empty, yet no suite applies to the selected
        // protocol: must refuse (previously passed startup and failed every runtime handshake).
        ProxyCompanionProperties tls13SuitesForTls12Only = withTls(
                RelayTestFixtures.forwardAProperties(0, 8, legs, "127.0.0.1", 2776),
                List.of("TLSv1.2"), null, RelayTestFixtures.TLS13_SUITES);
        assertThatThrownBy(() -> new SmppLegTlsFactory(tls13SuitesForTls12Only, Runnable::run))
                .as("suites that apply to none of the selected protocols must refuse")
                .hasMessageContaining("apply to none of the selected protocols");

        // (e) the mirror: TLS-1.2-only suites with protocols=[TLSv1.3].
        ProxyCompanionProperties tls12SuitesForTls13Only = withTls(
                RelayTestFixtures.forwardAProperties(0, 8, legs, "127.0.0.1", 2776),
                List.of("TLSv1.3"), RelayTestFixtures.TLS12_SUITES, null);
        assertThatThrownBy(() -> new SmppLegTlsFactory(tls12SuitesForTls13Only, Runnable::run))
                .as("the mirrored non-applicability must refuse too")
                .hasMessageContaining("apply to none of the selected protocols");
    }

    /** AD-20: IP-literal routing targets disable endpoint identification; hostnames keep HTTPS on. */
    @Test
    @DisplayName("AD-20: isIpLiteral — dotted quads, bare/bracketed IPv6 are literals; hostnames are not")
    void ipLiteralDetection() {
        assertThat(SmppLegTlsFactory.isIpLiteral("127.0.0.1")).isTrue();
        assertThat(SmppLegTlsFactory.isIpLiteral("10.0.0.1")).isTrue();
        assertThat(SmppLegTlsFactory.isIpLiteral("::1")).isTrue();
        assertThat(SmppLegTlsFactory.isIpLiteral("[::1]")).isTrue();
        assertThat(SmppLegTlsFactory.isIpLiteral("reverse.internal")).isFalse();
        assertThat(SmppLegTlsFactory.isIpLiteral("smpp.example.com")).isFalse();
        // Review 2026-08-27: an invalid dotted-quad is NOT an IP literal — the resolver treats it as
        // a DNS name, so it must fall to hostname verification (ON), never silently disable it.
        assertThat(SmppLegTlsFactory.isIpLiteral("999.1.2.3")).as("octet > 255").isFalse();
        assertThat(SmppLegTlsFactory.isIpLiteral("010.1.2.3")).as("leading-zero octet (octal ambiguity)").isFalse();
        assertThat(SmppLegTlsFactory.isIpLiteral("255.255.255.255")).as("still a literal at the boundary").isTrue();
    }

    /**
     * AD-20 (review 2026-08-27): the egress engine's endpoint-identification parameter is pinned per
     * target shape — deleting or inverting the factory line stays invisible to every socket-level
     * test (all dials are IP-literal against an IP-SAN cert), so pin the engine state directly.
     */
    @Test
    @DisplayName("AD-20: egress endpoint identification — null for IP-literal targets, HTTPS for hostnames")
    void egressEndpointIdentificationIsPinnedPerTarget(@TempDir Path dir) {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        SmppLegTlsFactory ipLiteral = new SmppLegTlsFactory(
                RelayTestFixtures.forwardAProperties(0, 8, legs, "127.0.0.1", 2776), Runnable::run);
        EmbeddedChannel ipDial = new EmbeddedChannel();
        try {
            javax.net.ssl.SSLEngine engine = ipLiteral.newEgressSslHandler(ipDial.alloc(),
                    new ProxyCompanionProperties.RoutingEntry("carrierOne", "127.0.0.1", 2776, null)).engine();
            assertThat(engine.getSSLParameters().getEndpointIdentificationAlgorithm())
                    .as("IP-literal target: hostname verification OFF (AD-20)")
                    .isNull();
        } finally {
            ipDial.close();
        }
        SmppLegTlsFactory hostname = new SmppLegTlsFactory(
                RelayTestFixtures.forwardAProperties(0, 8, legs, "reverse.internal", 2776), Runnable::run);
        EmbeddedChannel hostDial = new EmbeddedChannel();
        try {
            javax.net.ssl.SSLEngine engine = hostname.newEgressSslHandler(hostDial.alloc(),
                    new ProxyCompanionProperties.RoutingEntry("carrierOne", "reverse.internal", 2776, null)).engine();
            assertThat(engine.getSSLParameters().getEndpointIdentificationAlgorithm())
                    .as("hostname target: JDK HTTPS verification ON (AD-20)")
                    .isEqualTo("HTTPS");
        } finally {
            hostDial.close();
        }
    }

    /**
     * Factory re-checks (review 2026-08-27, the resolveClientCert discipline): a directly-constructed
     * mode-c record with NULL material must refuse here, not silently downgrade the runtime — a null
     * trust-store would run the REQUIRE listener at ClientAuth.NONE; a null instance cert would dial
     * cert-less against a REQUIRE reverse (every handshake failing at runtime).
     */
    @Test
    @DisplayName("null mode-c material bypassing the validator: null trust-store (SEC-050) / null client-cert (SEC-057) refuse")
    void nullModeCMaterialRefusesAtTheFactory(@TempDir Path dir) {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        ProxyCompanionProperties reverseBase =
                RelayTestFixtures.reverseCProperties(0, 8, legs, "smsc.example", 2775);
        ProxyCompanionProperties reverseCNoStore = new ProxyCompanionProperties(
                reverseBase.bind(), reverseBase.memory(), reverseBase.tls(), null,
                new ProxyCompanionProperties.Reverse(null, null,
                        new ProxyCompanionProperties.ReverseModeC(
                                reverseBase.reverse().modeC().smsc(),
                                reverseBase.reverse().modeC().serverCert(),
                                null, // the bypassed-validator null
                                reverseBase.reverse().modeC().oidc())));
        assertThatThrownBy(() -> new SmppLegTlsFactory(reverseCNoStore, Runnable::run))
                .as("a null REQUIRE-side store must refuse — never a silent ClientAuth.NONE")
                .hasMessageContaining("SEC-050");

        ProxyCompanionProperties forwardBase =
                RelayTestFixtures.forwardCProperties(0, 8, legs, "127.0.0.1", 2776);
        ProxyCompanionProperties forwardCNoCert = new ProxyCompanionProperties(
                forwardBase.bind(), forwardBase.memory(), forwardBase.tls(),
                new ProxyCompanionProperties.Forward(
                        null,
                        new ProxyCompanionProperties.ForwardModeC(
                                null, // the bypassed-validator null
                                forwardBase.forward().modeC().trustStore(),
                                forwardBase.forward().modeC().routing()),
                        null),
                null);
        assertThatThrownBy(() -> new SmppLegTlsFactory(forwardCNoCert, Runnable::run))
                .as("a null per-instance dial cert must refuse — never a cert-less dial")
                .hasMessageContaining("SEC-057");
    }

    /** AD-29/AD-13: the contexts map overrides the instance cert per routing entry; a dangling id fails closed. */
    @Test
    @DisplayName("AD-29: tls-context-id selects the companion.forward.tls-contexts override; a dangling id refuses (SEC-098)")
    void tlsContextOverrideResolution(@TempDir Path dir) {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);

        // (a) a RESOLVING override builds (mode-a + per-target client cert — a legal per-target posture).
        ProxyCompanionProperties overridden = withTls(RelayTestFixtures.forwardAProperties(0, 8, legs, "127.0.0.1", 2776),
                RelayTestFixtures.TLS_PROTOCOLS, RelayTestFixtures.TLS12_SUITES, RelayTestFixtures.TLS13_SUITES);
        ProxyCompanionProperties withOverride = new ProxyCompanionProperties(
                overridden.bind(), overridden.memory(),
                new ProxyCompanionProperties.Tls(overridden.tls().protocols(), overridden.tls().tls12CipherSuites(),
                        overridden.tls().tls13CipherSuites()),
                new ProxyCompanionProperties.Forward(
                        new ProxyCompanionProperties.ForwardModeA(
                                overridden.forward().modeA().trustStore(),
                                List.of(new ProxyCompanionProperties.RoutingEntry("carrierOne", "127.0.0.1", 2776, "primary"))),
                        null,
                        Map.of("primary", new ProxyCompanionProperties.ClientCert(
                                legs.forwardClientCert().toString(), legs.forwardClientKey().toString()))),
                null);
        SmppLegTlsFactory factory = new SmppLegTlsFactory(withOverride, Runnable::run);
        assertThat(factory.egressTls()).as("the override context builds and indexes the entry").isTrue();

        // (b) a DANGLING id (validator-neutralized path — the factory's own defensive re-check) refuses.
        ProxyCompanionProperties dangling = new ProxyCompanionProperties(
                withOverride.bind(), withOverride.memory(),
                withOverride.tls(),
                new ProxyCompanionProperties.Forward(
                        new ProxyCompanionProperties.ForwardModeA(
                                withOverride.forward().modeA().trustStore(),
                                List.of(new ProxyCompanionProperties.RoutingEntry("carrierOne", "127.0.0.1", 2776, "ghost"))),
                        null, null),
                null);
        assertThatThrownBy(() -> new SmppLegTlsFactory(dangling, Runnable::run))
                .as("a dangling tls-context-id must fail closed (SEC-098)")
                .hasMessageContaining("SEC-098");

        // (c) an UNREFERENCED entry with unloadable material refuses (SEC-100/AD-18, review
        // 2026-08-27): without the eager orphan pass this dead config would escape ALL validation
        // (the validator checks only id membership; the dial path never loads it).
        ProxyCompanionProperties orphanGarbage = new ProxyCompanionProperties(
                withOverride.bind(), withOverride.memory(), withOverride.tls(),
                new ProxyCompanionProperties.Forward(
                        withOverride.forward().modeA(),
                        null,
                        Map.of("primary", new ProxyCompanionProperties.ClientCert(
                                        legs.forwardClientCert().toString(), legs.forwardClientKey().toString()),
                                "orphan", new ProxyCompanionProperties.ClientCert(
                                        dir.resolve("no-such-cert.pem").toString(),
                                        dir.resolve("no-such-key.pem").toString()))),
                null);
        assertThatThrownBy(() -> new SmppLegTlsFactory(orphanGarbage, Runnable::run))
                .as("an unreferenced tls-contexts entry with unloadable material must refuse")
                .hasMessageContaining("does not exist");

        // (d) an unreferenced but VALID entry stays acceptable — a future routing target, not a boot failure.
        ProxyCompanionProperties orphanValid = new ProxyCompanionProperties(
                withOverride.bind(), withOverride.memory(), withOverride.tls(),
                new ProxyCompanionProperties.Forward(
                        withOverride.forward().modeA(),
                        null,
                        Map.of("primary", new ProxyCompanionProperties.ClientCert(
                                        legs.forwardClientCert().toString(), legs.forwardClientKey().toString()),
                                "future", new ProxyCompanionProperties.ClientCert(
                                        legs.foreignClientCert().toString(), legs.foreignClientKey().toString()))),
                null);
        assertThat(new SmppLegTlsFactory(orphanValid, Runnable::run).egressTls())
                .as("a valid unreferenced entry boots — only unloadable orphans refuse")
                .isTrue();
    }

    // --- helpers ---------------------------------------------------------------------------

    private static SmppLegTlsFactory forwardFactory(
            RelayTestFixtures.SmppTlsLegs legs, String trustStorePath, String password) {
        ProxyCompanionProperties base = RelayTestFixtures.forwardAProperties(0, 8, legs, "127.0.0.1", 2776);
        ProxyCompanionProperties mutated = new ProxyCompanionProperties(
                base.bind(), base.memory(), base.tls(),
                new ProxyCompanionProperties.Forward(
                        new ProxyCompanionProperties.ForwardModeA(
                                new ProxyCompanionProperties.TrustStore(trustStorePath, password),
                                base.forward().modeA().routing()),
                        null, null),
                null);
        return new SmppLegTlsFactory(mutated, Runnable::run);
    }

    private static ProxyCompanionProperties withTls(
            ProxyCompanionProperties base, List<String> protocols, List<String> tls12, List<String> tls13) {
        return new ProxyCompanionProperties(
                base.bind(), base.memory(),
                new ProxyCompanionProperties.Tls(protocols, tls12, tls13),
                base.forward(), base.reverse());
    }

    private static javax.net.ssl.SSLEngine listenerEngine(SmppLegTlsFactory factory) {
        EmbeddedChannel channel = new EmbeddedChannel();
        try {
            return factory.newIngressSslHandler(channel.alloc()).engine();
        } finally {
            channel.close();
        }
    }
}
