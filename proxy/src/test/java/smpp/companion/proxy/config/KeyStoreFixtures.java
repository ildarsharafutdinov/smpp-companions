package smpp.companion.proxy.config;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Trust-store fixtures for SEC-050 (the 5 invalid states) and the SEC-050 "passing" valid store. All
 * built from a single embedded self-signed PEM cert via the JDK-standard {@link CertificateFactory} —
 * no reach into {@code sun.security..} (SEC-090 stays clean; this is a config-package test fixture).
 */
final class KeyStoreFixtures {

    private KeyStoreFixtures() {}

    /** A self-signed root cert (CN=smpp-companions-test-root) valid 7 days — embedded, not generated at runtime. */
    static final String PEM_CERT = """
            -----BEGIN CERTIFICATE-----
            MIIDCTCCAfGgAwIBAgIIUJZ3QJ6ISCYwDQYJKoZIhvcNAQELBQAwMzENMAsGA1UE
            ChMEdGVzdDEiMCAGA1UEAxMZc21wcC1jb21wYW5pb25zLXRlc3Qtcm9vdDAeFw0y
            NjA4MDMxNTIzNTVaFw0yNjA4MTAxNTIzNTVaMDMxDTALBgNVBAoTBHRlc3QxIjAg
            BgNVBAMTGXNtcHAtY29tcGFuaW9ucy10ZXN0LXJvb3QwggEiMA0GCSqGSIb3DQEB
            AQUAA4IBDwAwggEKAoIBAQC8jDaBy722Y//cO2rqPlu60xUSEQBf61sxrwW28AuP
            IG0UIQNKxnOPqTS9ZRq3Xfav2sWIrAqy2+Dxpw4FbTF1uOT9FZrRuTz0I9pdUogu
            VqKKMdMeFtQj9Hi/LhQ95hDUTIHOVRT17VxYX3k0agDY+TIfNcLZIfDh4YSgXu5t
            Fds0+TRGUV3hszKWrAPRxc0CSUE+f+S7GXP9YGqYKNsBlfCqX1DtrlTnUZOy1E/M
            edD5oaApCeUIUOaM4m4BklwNxmhOOsmTKczj8ZY2UM5KSyF/+5jHP206swH6hQ0A
            jNz2zFzNZxjpxoXUfmnIzsT4GY45DfpFI0pi2b9FXNcbAgMBAAGjITAfMB0GA1Ud
            DgQWBBR4TJXvnvq9xpif0QlP6aqg0jyA2DANBgkqhkiG9w0BAQsFAAOCAQEADk5c
            yKQXDUkRJ18VjUXAS41zPkVK5mXpKhYwT+m4OCjMVO7bWVZWRsFnqBvFmmTQAeQQ
            yKfP5hW5WkYQfASEVa0s5iXNgXr4sc8M20u/UqRz4apSzzEgNIxJ58FbuAoYM7d1
            TvtKVBKZjq5c0f2lKorylW1ndYUyp87mFyWvYkzG9Be91vLNikM6Xe51vmUQCGDg
            skAyVM61Simcf6uRGMr7RcWciWbIlPnH1gIaYPmIxbqiz9UJwQXpzXfWrjPTlZ8c
            gGsDkGVkjKsu1HKXZ2yx8kNKseg89nJDdesocyvATlXg2SGawf31NZkX65m56cmZ
            FCadg3KyoeTndLicpw==
            -----END CERTIFICATE-----""";

    /** A valid PKCS12 trust store with ONE trustedCertEntry — the SEC-050 "passing" fixture. */
    static X509Certificate loadCert() throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(PEM_CERT.getBytes(StandardCharsets.UTF_8)));
    }

    /** A valid PKCS12 trust store with ONE trustedCertEntry — the SEC-050 "passing" fixture. */
    static Path writeValidTrustStore(Path file, String password) throws Exception {
        KeyStore ks = newEmptyKeyStore(password);
        ks.setCertificateEntry("smsc-root", loadCert());
        store(ks, file, password);
        return file;
    }

    /** A valid PKCS12 keystore with ZERO entries (SEC-050 zero-trustedCertEntry state). */
    static Path writeZeroEntryTrustStore(Path file, String password) throws Exception {
        store(newEmptyKeyStore(password), file, password);
        return file;
    }

    private static KeyStore newEmptyKeyStore(String password) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, password.toCharArray());
        return ks;
    }

    private static void store(KeyStore ks, Path file, String password) throws Exception {
        try (OutputStream out = Files.newOutputStream(file)) {
            ks.store(out, password.toCharArray());
        }
    }
}
