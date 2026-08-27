package smpp.companion.proxy.security;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import smpp.companion.proxy.config.ProxyCompanionProperties;

/**
 * Story 3.2 T2 (AC7) — the IdP client {@link SSLContext} factory: the TLS underpinning of the
 * proxy&rarr;provider link (discovery now; the ROPC token/JWKS calls from T3 on).
 * Every <b>reverse</b> cell's {@code companion.reverse.mode-*.oidc.trust-store} is loaded at bean
 * initialization at the full AD-13 depth &mdash; the 5-state PKIX load the T1 config validator
 * deliberately defers here (user amendment 2, 2026-08-18): a bad store (wrong format, wrong
 * password, empty, zero {@code trustedCertEntry}) refuses startup as the standard Spring startup
 * failure, fail-closed. The store is the <b>dedicated IdP trust anchor</b> &mdash; JDK
 * {@code cacerts} is never a fallback (AD-13/AD-26), and validation rides the JDK-default
 * {@link TrustManagerFactory} algorithm with PKIX defaults: no custom chain-validation code, no
 * {@code PKIXBuilderParameters} overrides (AD-13). Client auth toward the provider is the ROPC
 * {@code client_secret} in the token-endpoint form (the RFC 8705 keystore arm was removed
 * pre-release, 2026-08-19), so the context is <b>trust-only</b> &mdash; no key managers.
 *
 * <p><b>AD-34 intersection (decision D2's discharge for the IdP context).</b> The bind-time
 * validator proves {@code companion.tls.*} intersects the <i>JDK-default</i> context; this factory
 * re-intersects against <i>this</i> context's supported suites/protocols and refuses on empty
 * &mdash; the per-context gate D2 reserved for Epic 3. The surviving intersection (configured order
 * preserved) becomes the {@link SSLParameters} every provider-facing {@code HttpClient} request
 * carries, so an unsupported suite name can never reach an {@code SSLEngine}. Forward cells carry
 * no {@code oidc} node (AD-12 amended 2026-08-18: the reverse role adjudicates; the forward is a
 * trusted-side relay) &mdash; the factory stays {@linkplain #active() inactive} there and never
 * refuses a forward boot.
 */
@Component
public final class IdpSslContextFactory {

    private final @Nullable SSLContext sslContext;
    private final @Nullable SSLParameters sslParameters;
    private final @Nullable ResolvedOidc resolvedOidc;

    /**
     * Eager, fail-closed construction (the DirectMemoryBudgetStartupCheck pattern): the store load
     * and the AD-34 intersection run during context refresh, so a refusal aborts the boot before
     * any channel opens.
     *
     * @param properties the validated {@code companion.*} record; exactly one role&times;mode
     *        branch is populated (AD-17 compact-ctor guarantee)
     */
    public IdpSslContextFactory(ProxyCompanionProperties properties) {
        Objects.requireNonNull(properties, "properties");
        ResolvedOidc resolved = resolveOidc(properties);
        this.resolvedOidc = resolved;
        if (resolved == null) {
            // Forward cells carry no oidc node (AD-12 amended 2026-08-18) — there is no provider
            // link on this cell; the accessors below fail fast instead of returning null.
            this.sslContext = null;
            this.sslParameters = null;
            return;
        }
        SSLContext context = buildContext(loadIdpTrustStore(resolved));
        this.sslContext = context;
        this.sslParameters = intersectTlsPolicy(context,
                properties.tls().protocols(), properties.tls().tls12CipherSuites(), properties.tls().tls13CipherSuites());
    }

    /** Whether this cell has an IdP link at all (every reverse cell: yes; forward cells: no). */
    public boolean active() {
        return sslContext != null;
    }

    /** The trust-only IdP {@link SSLContext}; fails fast on inactive (forward) cells. */
    public SSLContext sslContext() {
        SSLContext context = sslContext;
        if (context == null) {
            throw new IllegalStateException(
                    "no IdP SSLContext on this cell — forward cells carry no companion.*.oidc node (AD-12 amended 2026-08-18).");
        }
        return context;
    }

    /** The AD-34-intersected parameters for every provider-facing request; fails fast on inactive cells. */
    public SSLParameters sslParameters() {
        SSLParameters parameters = sslParameters;
        if (parameters == null) {
            throw new IllegalStateException(
                    "no IdP SSLParameters on this cell — forward cells carry no companion.*.oidc node (AD-12 amended 2026-08-18).");
        }
        return parameters;
    }

    /** The resolved reverse-cell oidc node + its config-key prefix; {@code null} on forward cells. */
    public @Nullable ResolvedOidc resolvedOidc() {
        return resolvedOidc;
    }

    /**
     * A provider-facing {@link HttpClient} with THIS factory's TLS posture — the single
     * construction recipe (the adapter's 2-arg ctor builds its one shared client exactly here;
     * the T6 recording-wrapper tests wrap the same build). Fails fast on forward cells via the
     * accessors above; {@code connectTimeout} is the configured {@code oidc.timeout}
     * (per-request budgets are the caller's business).
     */
    public HttpClient newClient() {
        ResolvedOidc resolved = Objects.requireNonNull(resolvedOidc(),
                "no IdP link on this cell — forward cells carry no companion.*.oidc node "
                        + "(AD-12 amended 2026-08-18).");
        return HttpClient.newBuilder()
                .sslContext(sslContext())
                .sslParameters(sslParameters())
                .connectTimeout(resolved.oidc().timeout())
                .build();
    }

    // --- construction steps ------------------------------------------------------------------

    /**
     * Exactly one reverse mode-leaf is populated when a reverse branch exists (AD-17 compact ctor);
     * the first non-null leaf wins. Forward cells resolve to {@code null}.
     */
    private static @Nullable ResolvedOidc resolveOidc(ProxyCompanionProperties properties) {
        ProxyCompanionProperties.@Nullable Reverse reverse = properties.reverse();
        if (reverse == null) {
            return null;
        }
        if (reverse.modeA() != null) {
            return new ResolvedOidc("companion.reverse.mode-a", reverse.modeA().oidc());
        }
        if (reverse.modeB() != null) {
            return new ResolvedOidc("companion.reverse.mode-b", reverse.modeB().oidc());
        }
        if (reverse.modeC() != null) {
            return new ResolvedOidc("companion.reverse.mode-c", reverse.modeC().oidc());
        }
        return null;
    }

    /**
     * The 5-state AD-13 load the config validator defers here (T1 amendment 2): not-readable /
     * empty / wrong-format / wrong-password / zero-{@code trustedCertEntry} all refuse. The
     * not-exists / not-readable states are re-checked (not just trusted to the bind-time validator)
     * so a directly-constructed record fails with the same AD-13 posture. The password buffer is
     * zeroized on every path (AD-10 secret hygiene).
     */
    private static KeyStore loadIdpTrustStore(ResolvedOidc resolved) {
        ProxyCompanionProperties.TrustStore trustStore = resolved.oidc().trustStore();
        String key = resolved.keyPrefix() + ".oidc.trust-store.path";
        Path path = Path.of(trustStore.path());
        if (!Files.isReadable(path)) {
            throw new IllegalStateException(key + "=" + trustStore.path()
                    + " does not exist or is not readable — refusing to start (SEC-050/AD-13).");
        }
        char[] password = trustStore.password() == null ? null : trustStore.password().toCharArray();
        try {
            if (Files.size(path) == 0L) {
                throw new IllegalStateException(key + "=" + trustStore.path()
                        + " is empty (zero bytes) — refusing to start (SEC-050/AD-13).");
            }
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream in = Files.newInputStream(path)) {
                store.load(in, password);   // wrong format / wrong password throw here
            }
            int trusted = 0;
            for (String alias : Collections.list(store.aliases())) {
                if (store.isCertificateEntry(alias)) {
                    trusted++;
                }
            }
            if (trusted == 0) {
                throw new IllegalStateException(key + "=" + trustStore.path()
                        + " contains zero trustedCertEntry entries (an anchor-less store would trust nothing"
                        + " — never a cacerts fallback) — refusing to start (SEC-050/AD-13).");
            }
            return store;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(key + "=" + trustStore.path()
                    + " is not a valid trust store (" + e.getClass().getSimpleName() + ": " + e.getMessage()
                    + "). PKCS12 is expected on JDK 9+ — refusing to start (SEC-050/AD-13).", e);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');   // AD-10: zeroize the password buffer
            }
        }
    }

    /**
     * JDK-only context: the default {@link TrustManagerFactory} algorithm with PKIX defaults over
     * the dedicated store; no key managers (client auth is the ROPC {@code client_secret}, T3).
     */
    private static SSLContext buildContext(KeyStore trustStore) {
        try {
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagerFactory.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException e) {
            // Compiler-required catch (getInstance/init declare checked exceptions); on JDK 25 with
            // no SecurityManager these do not throw in practice — the validator's SSLContext catch
            // carries the same note. Fail-closed regardless: an unexpected failure refuses startup.
            throw new IllegalStateException(
                    "could not build the IdP client SSLContext (" + e.getClass().getSimpleName()
                            + ") — refusing to start (AD-13).", e);
        }
    }

    /**
     * The AD-34 per-context intersection (D2 discharge): configured suites/protocols &cap; THIS
     * context's supported sets; empty on either axis refuses. The intersection — never the raw
     * configured lists — becomes the effective {@link SSLParameters}.
     */
    private static SSLParameters intersectTlsPolicy(SSLContext context,
                                                    @Nullable List<String> protocols,
                                                    @Nullable List<String> tls12CipherSuites,
                                                    @Nullable List<String> tls13CipherSuites) {
        SSLParameters supported = context.getSupportedSSLParameters();
        Set<String> supportedSuites = Set.of(supported.getCipherSuites());
        Set<String> supportedProtocols = Set.of(supported.getProtocols());
        List<String> configuredSuites = new ArrayList<>();
        if (tls12CipherSuites != null) {
            configuredSuites.addAll(tls12CipherSuites);
        }
        if (tls13CipherSuites != null) {
            configuredSuites.addAll(tls13CipherSuites);
        }
        List<String> suites = configuredSuites.stream()
                .filter(supportedSuites::contains)
                .toList();
        if (suites.isEmpty()) {
            throw new IllegalStateException("companion.tls cipher suites have an empty intersection with the IdP "
                    + "client SSLContext's supported suites — refusing to start (AD-34, D2 discharge for the IdP context).");
        }
        List<String> effectiveProtocols = (protocols == null ? List.<String>of() : protocols).stream()
                .filter(supportedProtocols::contains)
                .toList();
        if (effectiveProtocols.isEmpty()) {
            throw new IllegalStateException("companion.tls.protocols have an empty intersection with the IdP "
                    + "client SSLContext's supported protocols — refusing to start (AD-34, D2 discharge for the IdP context).");
        }
        return new SSLParameters(
                suites.toArray(String[]::new), effectiveProtocols.toArray(String[]::new));
    }

    /**
     * The resolved reverse-cell oidc node with the config-key prefix its refusal messages cite
     * (e.g. {@code companion.reverse.mode-b}) — one resolution shared by every IdP-link component
     * so the leaf-selection cannot drift between them.
     */
    public record ResolvedOidc(String keyPrefix, ProxyCompanionProperties.Oidc oidc) {

        public ResolvedOidc {
            // Not jakarta annotations: no Bean-Validation pass ever runs over this programmatic
            // record (BV fires only on the Spring-bound config records) — requireNonNull is the guard.
            Objects.requireNonNull(keyPrefix, "keyPrefix");
            Objects.requireNonNull(oidc, "oidc");
        }
    }
}
