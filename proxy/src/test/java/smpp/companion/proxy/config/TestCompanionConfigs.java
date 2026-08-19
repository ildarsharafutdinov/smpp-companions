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
 * {@code args()} feeds {@code SpringApplicationBuilder.run}.
 */
final class TestCompanionConfigs {

    private static final String TLS12 = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
            + "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
            + "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
            + "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    private static final String TLS13 = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256";

    private final Map<String, String> props = new LinkedHashMap<>();

    private TestCompanionConfigs() {}

    /** forward × A (internet leg, one-way TLS): server cert+key + routing — NO OIDC (trusted-side relay; SEC-097 positive: no SMSC). */
    static TestCompanionConfigs forwardA(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        String b = "companion.forward.mode-a";
        c.props.put(b + ".server-cert.cert-path", touch(secrets.resolve("server.crt")).toString());
        c.props.put(b + ".server-cert.key-path", touch(secrets.resolve("server.key")).toString());
        c.props.put(b + ".routing[0].system-id", "carrierOne");
        c.props.put(b + ".routing[0].host", "reverse.internal");
        c.props.put(b + ".routing[0].port", "2776");
        return c;
    }

    /** forward × C: forward-A material + trust store (mTLS to the reverse proxy). */
    static TestCompanionConfigs forwardC(Path secrets) {
        TestCompanionConfigs c = forwardA(secrets);
        // Re-key the forward material under mode-c, then add the trust store.
        c.rekey("companion.forward.mode-a", "companion.forward.mode-c");
        String b = "companion.forward.mode-c";
        Path ts = trustStoreFixture(secrets.resolve("truststore.p12"));
        c.props.put(b + ".trust-store.path", ts.toString());
        c.props.put(b + ".trust-store.password", "changeit");
        return c;
    }

    /** reverse × A (internet leg, one-way TLS): SMSC + client trust store (internet-leg anchor, SEC-096) + OIDC. */
    static TestCompanionConfigs reverseA(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        String b = "companion.reverse.mode-a";
        c.props.put(b + ".smsc.host", "smsc.carrier.example");
        c.props.put(b + ".smsc.port", "2775");
        Path ts = trustStoreFixture(secrets.resolve("truststore.p12"));
        c.props.put(b + ".trust-store.path", ts.toString());
        c.props.put(b + ".trust-store.password", "changeit");
        c.oidcKeys(b, secrets);
        return c;
    }

    /** reverse × B: plaintext internet leg (direct client→reverse). acknowledged=true so the base is valid (SEC-052 warn+ack+start) + OIDC. */
    static TestCompanionConfigs reverseB(Path secrets) {
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

    /** reverse × C (internet leg, mTLS): SMSC + client cert+key (SEC-057) + trust store + OIDC. */
    static TestCompanionConfigs reverseC(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        String b = "companion.reverse.mode-c";
        c.props.put(b + ".smsc.host", "smsc.carrier.example");
        c.props.put(b + ".smsc.port", "2775");
        c.props.put(b + ".client-cert.cert-path", touch(secrets.resolve("client.crt")).toString());
        c.props.put(b + ".client-cert.key-path", touch(secrets.resolve("client.key")).toString());
        Path ts = trustStoreFixture(secrets.resolve("truststore.p12"));
        c.props.put(b + ".trust-store.path", ts.toString());
        c.props.put(b + ".trust-store.password", "changeit");
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
     * signed the stand-in's server cert, so the config stays valid from T2 on). The three budget keys
     * are REQUIRED — stated explicitly at the yml-template defaults (the
     * companion.bind.adjudication-deadline T7 pattern: runner boots don't load application.yml).
     */
    private void oidcKeys(String b, Path secrets) {
        props.put(b + ".oidc.provider-url", OidcDiscoveryStandIn.url());
        props.put(b + ".oidc.client-id", "smpp-client-confidential");
        props.put(b + ".oidc.client-secret-path", touch(secrets.resolve("oidc-client-secret")).toString());
        Path idpTrustStore = RelayTestFixtures.idpTrustStoreFixture(secrets.resolve("idp-truststore.p12"));
        props.put(b + ".oidc.trust-store.path", idpTrustStore.toString());
        props.put(b + ".oidc.trust-store.password", RelayTestFixtures.IDP_STORE_PASSWORD);
        props.put(b + ".oidc.timeout", "4s");
        props.put(b + ".oidc.max-in-flight", "64");
        props.put(b + ".oidc.jwks-cache-ttl", "5m");
    }

    private void common() {
        props.put("companion.tls.protocols", "TLSv1.3,TLSv1.2");
        props.put("companion.tls.tls12-cipher-suites", TLS12);
        props.put("companion.tls.tls13-cipher-suites", TLS13);
        // Story 2.2 T6: a VALID mode-b full-context boot now BINDS companion.bind.port (the relay
        // acceptor lifecycle, RelayServerLifecycle). A per-instance free ephemeral port keeps those
        // boots off the shipped 2775 default — deterministic against a locally-listening SMPP tool and
        // against other tests. (Forward-cell configs never bind — the lifecycle is mode-b-scoped — but
        // sharing the probe keeps every base uniform.)
        props.put("companion.bind.port", String.valueOf(RelayTestFixtures.freePort()));
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

    /** Re-keys every property whose key starts with {@code from} to start with {@code to}. */
    private void rekey(String from, String to) {
        Map<String, String> updated = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : props.entrySet()) {
            String key = e.getKey().startsWith(from) ? to + e.getKey().substring(from.length()) : e.getKey();
            updated.put(key, e.getValue());
        }
        props.clear();
        props.putAll(updated);
    }

    private static Path touch(Path p) {
        try {
            return Files.createFile(p);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Path trustStoreFixture(Path file) {
        try {
            return KeyStoreFixtures.writeValidTrustStore(file, "changeit");
        } catch (Exception e) {
            throw new IllegalStateException("failed to build trust store fixture " + file, e);
        }
    }

    TestCompanionConfigs put(String key, String value) {
        props.put(key, value);
        return this;
    }

    TestCompanionConfigs remove(String key) {
        props.remove(key);
        return this;
    }

    /** Property-value pairs for {@code ApplicationContextRunner.withPropertyValues(...)}. */
    String[] propertyValues() {
        return props.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue()).toArray(String[]::new);
    }

    /** {@code --key=value} args for {@code SpringApplicationBuilder.run(...)}. */
    String[] args() {
        return props.entrySet().stream().map(e -> "--" + e.getKey() + "=" + e.getValue()).toArray(String[]::new);
    }
}
