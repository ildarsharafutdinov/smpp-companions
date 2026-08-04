package smpp.companion.proxy.config;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

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

    /** forward × A: server cert+key + routing + OIDC (no SMSC — SEC-097 positive). */
    static TestCompanionConfigs forwardA(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        String b = "companion.forward.mode-a";
        c.props.put(b + ".server-cert.cert-path", touch(secrets.resolve("server.crt")).toString());
        c.props.put(b + ".server-cert.key-path", touch(secrets.resolve("server.key")).toString());
        c.props.put(b + ".routing[0].system-id", "carrierOne");
        c.props.put(b + ".routing[0].host", "reverse.internal");
        c.props.put(b + ".routing[0].port", "2776");
        c.props.put(b + ".oidc.provider-url", "https://idp.example.com");
        c.props.put(b + ".oidc.client-credential-path", touch(secrets.resolve("oidc-cred")).toString());
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

    /** reverse × A: SMSC + client trust store (forward/SMSC server-cert anchor, SEC-096). */
    static TestCompanionConfigs reverseA(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        String b = "companion.reverse.mode-a";
        c.props.put(b + ".smsc.host", "smsc.carrier.example");
        c.props.put(b + ".smsc.port", "2775");
        Path ts = trustStoreFixture(secrets.resolve("truststore.p12"));
        c.props.put(b + ".trust-store.path", ts.toString());
        c.props.put(b + ".trust-store.password", "changeit");
        return c;
    }

    /** reverse × B: plaintext. acknowledged=true so the base is valid (SEC-052 warn+ack+start). */
    static TestCompanionConfigs reverseB(Path secrets) {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        String b = "companion.reverse.mode-b";
        c.props.put(b + ".smsc.host", "smsc.carrier.example");
        c.props.put(b + ".smsc.port", "2775");
        c.props.put(b + ".acknowledged", "true");
        return c;
    }

    /** reverse × C: SMSC + client cert+key (mTLS, SEC-057) + trust store. */
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
        return c;
    }

    /** A valid base with NO branch at all (only common keys) — for the zero-branch refusal test. */
    static TestCompanionConfigs noBranch() {
        TestCompanionConfigs c = new TestCompanionConfigs();
        c.common();
        return c;
    }

    private void common() {
        props.put("companion.tls.protocols", "TLSv1.3,TLSv1.2");
        props.put("companion.tls.tls12-cipher-suites", TLS12);
        props.put("companion.tls.tls13-cipher-suites", TLS13);
        props.put("companion.bind.port", "2775");
        // max-frame + max-command-length are deliberately unset: they default to SmppFrame.MAX_COMMAND_LENGTH
        // in Java (RELAY-026), not a YAML literal.
        props.put("companion.memory.max-inbound-depth", "64");
        props.put("companion.memory.concurrent-pairs", "1024");
        props.put("companion.memory.safety-factor", "1.5");
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
