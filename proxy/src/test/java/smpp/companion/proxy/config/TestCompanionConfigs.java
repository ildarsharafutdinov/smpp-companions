package smpp.companion.proxy.config;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import smpp.companion.proxy.testsupport.OidcDiscoveryStandIn;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

/**
 * Builds COMPLETE, VALID {@code companion.*} property sets per AD-17 cell, creating the required
 * secret (empty) files + a valid trust store under a temp dir. The role&times;mode cell is selected
 * structurally &mdash; each factory populates exactly ONE branch
 * ({@code companion.<role>.<mode>.*}). Matrix tests copy a base, mutate one field to inject the bad
 * value, and assert the refusal (or, for SEC-097, the start). Every base is otherwise valid so the
 * ONLY failing condition is the one under test &mdash; the "make every assertion bite" discipline
 * (Story 1.2's vacuous-assertion lesson).
 *
 * <p>Checked exceptions from fixture file creation are wrapped so test methods stay clean.
 * {@code propertyValues()} feeds {@code ApplicationContextRunner.withPropertyValues};
 * {@code args()} feeds {@code SpringApplicationBuilder.run}. Public since Story 3.2 T7 — the
 * security-side wiring suite ({@code VerifierWiringConfigTest}) consumes the same five-cell bases
 * cross-package so the canonical cell configs have one source, not drifted copies.
 */
public final class TestCompanionConfigs {

    private static final String TLS12 = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
            + "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
            + "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
            + "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    private static final String TLS13 = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256";

    private final Map<String, String> props = new LinkedHashMap<>();

    private TestCompanionConfigs() {}

    // Story 3.3 ([B] re-shape): the forward cells carry the DIAL material (trust store [+ client
    // cert]); the reverse cells carry the LISTENER material (server cert [+ trust store in C]). The
    // TLS files are the committed SMPP-leg test PKI (RelayTestFixtures.smppTlsLegs) — REAL parseable
    // material, because every full-context boot constructs SmppLegTlsFactory, which loads it eagerly.

    /** forward × A (per-session one-way TLS dial): trust store + routing — NO OIDC (trusted-side relay; SEC-097 positive: no SMSC). */
    public static TestCompanionConfigs forwardA(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(secrets);
        String b = "companion.forward.mode-a";
        c.props.put(b + ".trust-store.path", legs.trustStore().toString());
        c.props.put(b + ".trust-store.password", RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD);
        c.props.put(b + ".routing[0].system-id", "carrierOne");
        c.props.put(b + ".routing[0].host", "reverse.internal");
        c.props.put(b + ".routing[0].port", "2776");
        return c;
    }

    /** forward × C: forward-A material + the per-instance client cert (mTLS dial to the reverse). */
    public static TestCompanionConfigs forwardC(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(secrets);
        String b = "companion.forward.mode-c";
        c.props.put(b + ".client-cert.cert-path", legs.forwardClientCert().toString());
        c.props.put(b + ".client-cert.key-path", legs.forwardClientKey().toString());
        c.props.put(b + ".trust-store.path", legs.trustStore().toString());
        c.props.put(b + ".trust-store.password", RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD);
        c.props.put(b + ".routing[0].system-id", "carrierOne");
        c.props.put(b + ".routing[0].host", "reverse.internal");
        c.props.put(b + ".routing[0].port", "2776");
        return c;
    }

    /** reverse × A (internet-leg TLS listener): SMSC + server cert+key + OIDC (no trust store — one-way presents, never validates). */
    public static TestCompanionConfigs reverseA(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(secrets);
        String b = "companion.reverse.mode-a";
        c.props.put(b + ".smsc.host", "smsc.carrier.example");
        c.props.put(b + ".smsc.port", "2775");
        c.props.put(b + ".server-cert.cert-path", legs.reverseServerCert().toString());
        c.props.put(b + ".server-cert.key-path", legs.reverseServerKey().toString());
        c.oidcKeys(b, secrets);
        return c;
    }

    /** reverse × B: plaintext internet leg (direct client→reverse). acknowledged=true so the base is valid (SEC-052 warn+ack+start) + OIDC. */
    public static TestCompanionConfigs reverseB(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        // The AD-30 budget comes minimal from common() (the self-check is unconditional — see common()).
        String b = "companion.reverse.mode-b";
        c.props.put(b + ".smsc.host", "smsc.carrier.example");
        c.props.put(b + ".smsc.port", "2775");
        c.props.put(b + ".acknowledged", "true");
        c.oidcKeys(b, secrets);
        return c;
    }

    /** reverse × C (internet-leg mTLS listener): SMSC + server cert+key + trust store (REQUIRE) + OIDC. */
    public static TestCompanionConfigs reverseC(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(secrets);
        String b = "companion.reverse.mode-c";
        c.props.put(b + ".smsc.host", "smsc.carrier.example");
        c.props.put(b + ".smsc.port", "2775");
        c.props.put(b + ".server-cert.cert-path", legs.reverseServerCert().toString());
        c.props.put(b + ".server-cert.key-path", legs.reverseServerKey().toString());
        c.props.put(b + ".trust-store.path", legs.trustStore().toString());
        c.props.put(b + ".trust-store.password", RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD);
        c.oidcKeys(b, secrets);
        return c;
    }

    /** A valid base with NO branch at all (only common keys) — for the zero-branch refusal test. */
    static TestCompanionConfigs noBranch() {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        return c;
    }

    /**
     * The Story 3.2 T1 oidc node (AC8; re-targeted to the reverse role by the AD-12 amendment of
     * 2026-08-18 — every reverse cell adjudicates). provider-url defaults to the shared HTTPS
     * discovery stand-in (its issuer echoes its base URL — what the T2 startup check requires);
     * provider client auth is the required client_secret arm (the RFC 8705 mTLS arm was removed
     * 2026-08-19); the IdP trust store anchors the fixture CA (which
     * signed the stand-in's server cert, so the config stays valid from T2 on). The two budget keys
     * are REQUIRED — stated explicitly at the yml-template defaults (the
     * companion.bind.adjudication-deadline T7 pattern: runner boots don't load application.yml).
     * (2026-08-27, Story 3.4 T2: the third former budget key — the key-cache TTL — was removed
     * with local JWT verification; configs here no longer carry it.)
     * The secret file carries REAL content (T7): full-app boots construct the ROPC adapter bean,
     * which loads it — an empty file would refuse startup (SEC-060).
     */
    private void oidcKeys(String b, Path secrets) {
        props.put(b + ".oidc.provider-url", OidcDiscoveryStandIn.url());
        props.put(b + ".oidc.client-id", "smpp-client-confidential");
        props.put(b + ".oidc.client-secret-path", secretFile(secrets.resolve("oidc-client-secret")).toString());
        Path idpTrustStore = RelayTestFixtures.idpTrustStoreFixture(secrets.resolve("idp-truststore.p12"));
        props.put(b + ".oidc.trust-store.path", idpTrustStore.toString());
        props.put(b + ".oidc.trust-store.password", RelayTestFixtures.IDP_STORE_PASSWORD);
        props.put(b + ".oidc.timeout", "4s");
        props.put(b + ".oidc.max-in-flight", "64");
    }

    private void common() {
        props.put("companion.tls.protocols", "TLSv1.3,TLSv1.2");
        props.put("companion.tls.tls12-cipher-suites", TLS12);
        props.put("companion.tls.tls13-cipher-suites", TLS13);
        // Story 2.2 T6: a VALID mode-b full-context boot now BINDS companion.bind.port (the relay
        // acceptor lifecycle, RelayServerLifecycle). A per-instance free ephemeral port keeps those
        // boots off the shipped 2775 default — deterministic against a locally-listening SMPP tool and
        // against other tests. (Since Story 3.3 EVERY cell binds — the acceptor is no longer
        // mode-b-scoped — so the shared probe matters for all of them.)
        props.put("companion.bind.port", String.valueOf(RelayTestFixtures.freePort()));
        // Story 3.3 / F13: the listener now binds host:port; the accepted-connection cap IS the
        // minimal AD-30 budget's concurrent-pairs=1 below (one number — the review-rework shape;
        // these runner configs never accept real connections; the wiring/e2e suites carry realistic
        // values).
        props.put("companion.bind.host", "127.0.0.1");
        // Story 2.2 T7 owner FIXME: companion.bind.adjudication-deadline is now a required key (the
        // ApplicationContextRunner boots below do NOT load application.yml, so the yml default cannot
        // supply it — every base carries the documented 4s default explicitly, the T5b no-@DefaultValue
        // pattern: the default lives in yml for real boots; test configs state it).
        props.put("companion.bind.adjudication-deadline", "4s");
        // max-frame + max-command-length are deliberately unset: they default to SmppFrame.MAX_COMMAND_LENGTH
        // in Java (RELAY-026), not a YAML literal.
        // Story 2.2 T5b: the AD-30 live direct-memory self-check (DirectMemoryBudgetStartupCheck) is
        // UNCONDITIONAL — every full-context boot, every role×mode cell, compares the derived budget to
        // the test JVM's live direct-memory ceiling. The realistic defaults (64 × 1024 × 1.5 ≈ 6 GiB)
        // exceed a capped test JVM's ceiling (e.g. 512 MiB), so every test config carries a minimal
        // budget (1 × 1 × 1.0 = 65536 bytes) that fits under it. The self-check still RUNS for every
        // boot (its fail and warn arms are exercised in DirectMemoryBudgetStartupCheckTest) — this only
        // keeps the budget inside the ceiling so a VALID boot can start.
        props.put("companion.memory.max-inbound-depth", "1");
        props.put("companion.memory.concurrent-pairs", "1");
        props.put("companion.memory.safety-factor", "1.0");
    }

    /**
     * A NON-BLANK client-secret file (T7): the adapter bean loads it at startup, and the trailing
     * newline keeps ClientSecret.load's ASCII-trim path exercised on every boot.
     */
    private static Path secretFile(Path p) {
        try {
            return Files.writeString(p, "stand-in-client-secret\n");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public TestCompanionConfigs put(String key, String value) {
        props.put(key, value);
        return this;
    }

    TestCompanionConfigs remove(String key) {
        props.remove(key);
        return this;
    }

    /** Property-value pairs for {@code ApplicationContextRunner.withPropertyValues(...)}. */
    public String[] propertyValues() {
        return props.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue()).toArray(String[]::new);
    }

    /** {@code --key=value} args for {@code SpringApplicationBuilder.run(...)}. */
    String[] args() {
        return props.entrySet().stream().map(e -> "--" + e.getKey() + "=" + e.getValue()).toArray(String[]::new);
    }
}
