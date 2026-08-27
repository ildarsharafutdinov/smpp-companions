package smpp.companion.proxy.tls;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;

import smpp.companion.proxy.config.ProxyCompanionProperties;

/**
 * Story 3.3 — the SMPP internet-leg TLS runtime under the user-ratified <b>[B]</b> topology
 * (2026-08-21: the forward dials the reverse per SMPP session; the reverse holds the internet-leg
 * TLS listener). One per-cell factory bean, built EAGER and FAIL-CLOSED at context refresh (the
 * {@code DirectMemoryBudgetStartupCheck} / {@code IdpSslContextFactory} pattern): a bad store
 * (5-state), an unparseable cert/key, or an empty AD-34 intersection on ANY context refuses startup
 * before any channel opens (AD-17/AD-11). Everything built here is IMMUTABLE after startup (AD-8 /
 * AD-18 — rotation = re-deploy).
 *
 * <p><b>What it builds per cell:</b>
 * <ul>
 *   <li><b>reverse.mode-a/c — the internet-leg listener context</b> (server cert+key; Mode C adds
 *       the trust store and {@link ClientAuth#REQUIRE REQUIRE} — never WANT, AD-11/AD-13).</li>
 *   <li><b>reverse.mode-b — nothing</b> (plaintext direct leg; the cell is byte-identical to 2.2).</li>
 *   <li><b>forward.mode-a/c — one client context per routing entry</b>, resolved at STARTUP: the
 *       cell's trust store (validating the reverse's server cert, AD-26 — never {@code cacerts}),
 *       plus the client cert selected by the entry's {@code tls-context-id} (the
 *       {@code companion.forward.tls-contexts} override), else the instance-level cert (Mode C),
 *       else none (Mode A one-way). Per-entry resolution at startup is what makes the dial-time
 *       path a pure lookup and keeps TLS material immutable (AD-8).</li>
 * </ul>
 *
 * <p><b>AD-20 endpoint-identification:</b> Netty 4.2 defaults client verification to {@code HTTPS},
 * which fails raw-IP connects; each egress context is built with the algorithm EXPLICIT — {@code
 * null} for IP-literal routing targets, {@code "HTTPS"} for hostname targets (IP-SAN-provisioned
 * certs with verification on is the alternative operator posture, AD-20).
 *
 * <p><b>JDK provider only</b> ({@link SslProvider#JDK} — no BouncyCastle, no tcnative), PKIX
 * defaults via the JDK-default {@link TrustManagerFactory} over the dedicated store: no custom
 * chain-validation code, no {@code PKIXBuilderParameters} (AD-13 — SEC-090's widened gate).
 *
 * <p>Every {@link SslHandler} this factory hands out carries the ONE bounded delegating-task
 * executor (AD-28(1)/AD-4 — {@link TlsWiringConfig#tlsDelegatedTaskExecutor()}), so handshake
 * crypto never runs on a relay event loop and saturation aborts the handshake.
 */
@Component
public final class SmppLegTlsFactory {

    private final Executor delegatedTaskExecutor;
    private final @Nullable SslContext listenerContext;
    private final Map<String, SslContext> egressContexts;

    /**
     * Eager, fail-closed construction.
     *
     * @param properties the validated {@code companion.*} record; exactly one role&times;mode
     *        branch is populated (AD-17 compact-ctor guarantee)
     * @param delegatedTaskExecutor the shared bounded handshake-crypto executor (AD-28(1)/AD-4)
     */
    public SmppLegTlsFactory(ProxyCompanionProperties properties,
                             @Qualifier("tlsDelegatedTaskExecutor") Executor delegatedTaskExecutor) {
        Objects.requireNonNull(properties, "properties");
        this.delegatedTaskExecutor = Objects.requireNonNull(delegatedTaskExecutor, "delegatedTaskExecutor");
        ProxyCompanionProperties.@Nullable Reverse reverse = properties.reverse();
        ProxyCompanionProperties.@Nullable Forward forward = properties.forward();
        try {
            if (reverse != null) {
                this.listenerContext = buildListenerContext(properties, reverse);
                this.egressContexts = Map.of(); // the SMSC leg is plaintext in every mode (AD-12 amended)
            } else if (forward != null) {
                this.listenerContext = null;    // the trusted leg is plaintext (AD-15); the forward dials out
                this.egressContexts = buildEgressContexts(properties, forward);
            } else {
                // Unreachable post-validation (AD-17 compact ctor) — kept as a wiring-bug tripwire.
                throw new IllegalStateException(
                        "no companion.<role> branch is configured (AD-17) — refusing to start.");
            }
        } catch (SSLException | IllegalArgumentException e) {
            // IllegalArgumentException: Netty's PEM loaders reject unparseable cert/key material with
            // an IAE (not an SSLException) — same fail-closed wrap, the standard Spring refusal shape.
            throw new IllegalStateException("could not build the SMPP-leg TLS material ("
                    + e.getClass().getSimpleName() + ": " + e.getMessage() + ") — refusing to start (SEC-100/AD-13/AD-34).", e);
        }
    }

    // ---------------------------------------------------------------- listener (the reverse cells)

    /** Whether THIS cell's ingress pipeline must carry an {@link SslHandler} (reverse.mode-a/c). */
    public boolean listenerTls() {
        return listenerContext != null;
    }

    /**
     * The internet-leg listener handler for one accepted channel (added FIRST — before the framer,
     * the spine's {@code SslHandler → SmppFrameDecoder → …} pipeline order). One per channel: the
     * engine is per-connection state. Fails fast on cells without a TLS listener (a wiring bug, not
     * a data-plane condition).
     */
    public SslHandler newIngressSslHandler(ByteBufAllocator alloc) {
        SslContext context = listenerContext;
        if (context == null) {
            throw new IllegalStateException(
                    "no internet-leg TLS listener on this cell (reverse.mode-a/c only, [B] topology).");
        }
        return context.newHandler(alloc, delegatedTaskExecutor);
    }

    // ---------------------------------------------------------------- egress (the forward cells)

    /** Whether THIS cell's per-session dials are TLS (forward.mode-a/c — the reverse's SMSC leg never is). */
    public boolean egressTls() {
        return !egressContexts.isEmpty();
    }

    /**
     * The client handler for one per-session dial to the given routing entry's target (added FIRST
     * on the egress pipeline). The context was resolved at STARTUP from the entry's {@code
     * tls-context-id}; the peer host/port ride the engine (SNI + peer info). Fails fast on cells
     * without TLS egress or an entry this factory did not index (a wiring bug — both resolve from
     * the same validated properties).
     *
     * @param alloc the egress channel's allocator; non-null.
     * @param target the AD-29 routing entry being dialed; non-null.
     */
    public SslHandler newEgressSslHandler(ByteBufAllocator alloc, ProxyCompanionProperties.RoutingEntry target) {
        SslContext context = egressContexts.get(target.systemId());
        if (!egressTls() || context == null) {
            throw new IllegalStateException("no egress TLS context for system_id=" + target.systemId()
                    + " on this cell (forward.mode-a/c routing, [B] topology).");
        }
        return context.newHandler(alloc, target.host(), target.port(), delegatedTaskExecutor);
    }

    // ---------------------------------------------------------------- construction steps

    /**
     * reverse.mode-a: server cert+key only (one-way TLS — the listener PRESENTS a cert, it does not
     * validate peers; the [B] Mode A accepted-risk entry owns that posture). reverse.mode-c: adds
     * the trust store + {@link ClientAuth#REQUIRE} (AD-11/AD-13 — REQUIRE never WANT).
     */
    private static @Nullable SslContext buildListenerContext(
            ProxyCompanionProperties properties, ProxyCompanionProperties.Reverse reverse)
            throws SSLException {
        SslMaterial material;
        ClientAuth clientAuth = ClientAuth.NONE;
        if (reverse.modeA() != null) {
            material = new SslMaterial(reverse.modeA().serverCert(), null, "companion.reverse.mode-a");
        } else if (reverse.modeC() != null) {
            if (reverse.modeC().trustStore() == null) {
                // Factory re-check (the resolveClientCert discipline): a directly-constructed record
                // that bypassed the validator must fail the same fail-closed way — a null store here
                // would silently downgrade the REQUIRE listener to ClientAuth.NONE (code review 2026-08-27).
                throw new IllegalStateException("companion.reverse.mode-c.trust-store is required "
                        + "(the REQUIRE-side anchor) — refusing to start (SEC-050/AD-13).");
            }
            material = new SslMaterial(reverse.modeC().serverCert(), reverse.modeC().trustStore(),
                    "companion.reverse.mode-c");
            clientAuth = ClientAuth.REQUIRE;
        } else {
            return null; // reverse.mode-b — plaintext direct leg, byte-identical to Story 2.2
        }
        SslContextBuilder builder = SslContextBuilder
                .forServer(readable(material.prefix() + ".server-cert.cert-path", material.serverCert().certPath()),
                        readable(material.prefix() + ".server-cert.key-path", material.serverCert().keyPath()))
                .sslProvider(SslProvider.JDK);
        if (material.trustStore() != null) {
            builder.trustManager(loadTrustManagerFactory(material.trustStore(), material.prefix() + ".trust-store"))
                    .clientAuth(clientAuth);
        }
        return applyTlsPolicy(properties, material.prefix(), builder).build();
    }

    /**
     * forward.mode-a/c: one client context per routing entry — trust store (AD-26 anchor) + the
     * client cert selected by {@code tls-context-id} (contexts override → instance default (Mode C)
     * → none (Mode A)), with AD-20 endpoint-identification set per target host.
     */
    private static Map<String, SslContext> buildEgressContexts(
            ProxyCompanionProperties properties, ProxyCompanionProperties.Forward forward) throws SSLException {
        ProxyCompanionProperties.TrustStore trustStore;
        ProxyCompanionProperties.@Nullable ClientCert instanceCert;
        List<ProxyCompanionProperties.RoutingEntry> routing;
        String prefix;
        if (forward.modeA() != null) {
            trustStore = forward.modeA().trustStore();
            instanceCert = null;
            routing = forward.modeA().routing();
            prefix = "companion.forward.mode-a";
        } else if (forward.modeC() != null) {
            if (forward.modeC().clientCert() == null) {
                // Factory re-check (the resolveClientCert discipline): a null instance cert would dial
                // cert-less against a REQUIRE reverse — every handshake failing at runtime instead of
                // refusing here (code review 2026-08-27).
                throw new IllegalStateException("companion.forward.mode-c.client-cert is required "
                        + "(the per-instance dial identity) — refusing to start (SEC-057).");
            }
            trustStore = forward.modeC().trustStore();
            instanceCert = forward.modeC().clientCert();
            routing = forward.modeC().routing();
            prefix = "companion.forward.mode-c";
        } else {
            throw new IllegalStateException("no companion.forward.<mode> branch (AD-17) — refusing to start.");
        }
        Map<String, SslContext> contexts = new HashMap<>();
        java.util.Set<String> referenced = new java.util.HashSet<>();
        for (ProxyCompanionProperties.RoutingEntry entry : routing) {
            ProxyCompanionProperties.@Nullable ClientCert cert = resolveClientCert(properties, entry, instanceCert);
            SslContextBuilder builder = SslContextBuilder.forClient()
                    .sslProvider(SslProvider.JDK)
                    .trustManager(loadTrustManagerFactory(trustStore, prefix + ".trust-store"));
            if (cert != null) {
                builder.keyManager(
                        readable(prefix + " client cert", cert.certPath()), readable(prefix + " client key", cert.keyPath()));
            }
            // AD-20: Netty 4.2 defaults client verification to "HTTPS" (fails raw-IP connects) — make
            // the posture EXPLICIT per target: null for IP literals, HTTPS for hostnames.
            builder.endpointIdentificationAlgorithm(isIpLiteral(entry.host()) ? null : "HTTPS");
            if (entry.tlsContextId() != null) {
                referenced.add(entry.tlsContextId());
            }
            contexts.put(entry.systemId(),
                    applyTlsPolicy(properties, prefix + " (system_id=" + entry.systemId() + ")", builder).build());
        }
        // Story 3.3 review (SEC-100/AD-18): EVERY configured tls-contexts entry is loaded eagerly, not
        // just the routing-referenced ones. Without this pass an UNREFERENCED entry (a leftover from a
        // routing edit, or a typo'd id nothing selects) is dead secret-path config that escapes all
        // validation — the validator checks only id membership and the dial path never touches it. A
        // VALID unreferenced entry stays acceptable (a future routing target); an unloadable one refuses.
        Map<String, ProxyCompanionProperties.ClientCert> configured =
                forward.tlsContexts() == null ? Map.of() : forward.tlsContexts();
        for (Map.Entry<String, ProxyCompanionProperties.ClientCert> ctx : configured.entrySet()) {
            if (!referenced.contains(ctx.getKey())) {
                SslContextBuilder orphan = SslContextBuilder.forClient()
                        .sslProvider(SslProvider.JDK)
                        .trustManager(loadTrustManagerFactory(trustStore, prefix + ".trust-store"))
                        .keyManager(readable(prefix + " client cert (tls-contexts id=" + ctx.getKey() + ")",
                                        ctx.getValue().certPath()),
                                readable(prefix + " client key (tls-contexts id=" + ctx.getKey() + ")",
                                        ctx.getValue().keyPath()));
                applyTlsPolicy(properties, prefix + " (unreferenced tls-contexts id=" + ctx.getKey() + ")",
                        orphan).build(); // load-for-validation only — the built context is discarded
            }
        }
        return Collections.unmodifiableMap(contexts);
    }

    /** AD-29/AD-13: contexts-override → instance default → none; a dangling id is refused by SEC-098. */
    private static ProxyCompanionProperties.@Nullable ClientCert resolveClientCert(
            ProxyCompanionProperties properties, ProxyCompanionProperties.RoutingEntry entry,
            ProxyCompanionProperties.@Nullable ClientCert instanceCert) {
        String contextId = entry.tlsContextId();
        if (contextId == null) {
            return instanceCert;
        }
        // Forward-scoped (Story 3.3 review rework): only the forward dials TLS, so the override map
        // rides the forward branch — properties.forward() is non-null on every path that gets here.
        Map<String, ProxyCompanionProperties.ClientCert> contexts =
                properties.forward() == null ? null : properties.forward().tlsContexts();
        ProxyCompanionProperties.ClientCert override = contexts == null ? null : contexts.get(contextId);
        if (override == null) {
            // Unreachable post-SEC-098; re-checked here so a directly-constructed record fails the
            // same fail-closed way the validated path would.
            throw new IllegalStateException("routing entry tls-context-id=" + contextId
                    + " references no companion.forward.tls-contexts entry — refusing to start (SEC-098/AD-29).");
        }
        return override;
    }

    /**
     * The AD-34 per-context intersection (D2's discharge for the SMPP legs): configured suites and
     * protocols &cap; THIS cell's JDK supported sets — computed for EVERY context built (the listener
     * and each egress target); empty on either axis refuses. The JDK-default supported sets equal the
     * Netty JDK-provider context's supported sets (same JCA provider — the shipped IdP-factory and
     * bind-time-validator equivalence).
     */
    private static SslContextBuilder applyTlsPolicy(
            ProxyCompanionProperties properties, String what, SslContextBuilder builder) throws SSLException {
        ProxyCompanionProperties.Tls tls = properties.tls();
        List<String> protocols = tls == null ? null : tls.protocols();
        List<String> configuredSuites = new ArrayList<>();
        if (tls != null) {
            if (tls.tls12CipherSuites() != null) {
                configuredSuites.addAll(tls.tls12CipherSuites());
            }
            if (tls.tls13CipherSuites() != null) {
                configuredSuites.addAll(tls.tls13CipherSuites());
            }
        }
        try {
            SSLContext jdk = SSLContext.getInstance("TLS");
            jdk.init(null, null, null); // provider-global supported sets (JDK default)
            Set<String> supportedSuites = new java.util.HashSet<>(
                    Arrays.asList(jdk.getSocketFactory().getSupportedCipherSuites()));
            Set<String> supportedProtocols = new java.util.HashSet<>(
                    Arrays.asList(jdk.getSupportedSSLParameters().getProtocols()));
            List<String> suites = configuredSuites.stream().filter(supportedSuites::contains).toList();
            if (suites.isEmpty()) {
                throw new IllegalStateException("companion.tls cipher suites have an empty intersection with the "
                        + "JDK supported suites for the SMPP-leg context [" + what + "] — refusing to start "
                        + "(SEC-100/AD-34, D2 discharge).");
            }
            List<String> effectiveProtocols = (protocols == null ? List.<String>of() : protocols).stream()
                    .filter(supportedProtocols::contains)
                    .toList();
            if (effectiveProtocols.isEmpty()) {
                throw new IllegalStateException("companion.tls.protocols have an empty intersection with the JDK "
                        + "supported protocols for the SMPP-leg context [" + what + "] — refusing to start "
                        + "(SEC-100/AD-34, D2 discharge).");
            }
            // SEC-100/AD-34 applicability (code review 2026-08-27): the two intersections above run
            // independently — a suite set that intersects the JDK's supported list but applies to NONE of
            // the selected protocols (TLS-1.3-only suites with protocols=[TLSv1.2], or vice versa) would
            // pass this startup gate and then fail EVERY runtime handshake. Cross-check them: under the
            // JDK provider (SEC-090 pins it) the TLS-1.3 namespace is exactly the TLS_AES_*/TLS_CHACHA20_*
            // suites, so applicability is decided by name.
            boolean tls13Selected = effectiveProtocols.contains("TLSv1.3");
            boolean pre13Selected = effectiveProtocols.stream().anyMatch(p -> !"TLSv1.3".equals(p));
            boolean any13Suite = suites.stream().anyMatch(SmppLegTlsFactory::isTls13Suite);
            boolean anyPre13Suite = suites.stream().anyMatch(s -> !isTls13Suite(s));
            if ((any13Suite && !tls13Selected) || (anyPre13Suite && !pre13Selected)) {
                throw new IllegalStateException("companion.tls cipher suites apply to none of the selected "
                        + "protocols for the SMPP-leg context [" + what + "] — every handshake would fail — "
                        + "refusing to start (SEC-100/AD-34).");
            }
            return builder.protocols(effectiveProtocols).ciphers(suites);
        } catch (GeneralSecurityException e) {
            // Compiler-required (getInstance/init declare checked exceptions); on JDK 25 with no
            // SecurityManager these do not throw in practice (the IdpSslContextFactory note). Fail
            // closed regardless: an unexpected failure refuses startup.
            throw new IllegalStateException("could not compute the AD-34 intersection for [" + what
                    + "] (" + e.getClass().getSimpleName() + ") — refusing to start (SEC-100/AD-34).", e);
        }
    }

    /** Whether the suite name is in the JDK provider's fixed TLS-1.3 namespace (see {@link #applyTlsPolicy}). */
    private static boolean isTls13Suite(String suite) {
        return suite.startsWith("TLS_AES_") || suite.startsWith("TLS_CHACHA20_");
    }

    /**
     * The 5-state AD-13 load (absent / empty / wrong-format / wrong-password / zero {@code
     * trustedCertEntry} all refuse), fed to the JDK-default {@link TrustManagerFactory} — PKIX
     * defaults, no {@code PKIXBuilderParameters}, never a {@code cacerts} fallback. The password
     * buffer is zeroized on every path (AD-10).
     */
    private static TrustManagerFactory loadTrustManagerFactory(
            ProxyCompanionProperties.TrustStore trustStore, String key) {
        Path path = readablePath(key + ".path", trustStore.path());
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
            TrustManagerFactory factory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(store);
            return factory;
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

    /** Existence/readability re-check (not just trusted to bind-time validation — the IdP pattern). */
    private static Path readablePath(String key, String path) {
        Path resolved = Path.of(path);
        if (!Files.isReadable(resolved)) {
            throw new IllegalStateException(key + "=" + path
                    + " does not exist or is not readable — refusing to start (SEC-060/AD-18).");
        }
        return resolved;
    }

    /** {@link #readablePath} as the {@link java.io.File} the Netty PEM loaders take. */
    private static java.io.File readable(String key, String path) {
        return readablePath(key, path).toFile();
    }

    /**
     * AD-20's IP-literal test, dependency-free and DNS-free: bracketed or bare IPv6 (contains ':')
     * and dotted-quad IPv4. An ambiguous value falls to hostname-verification-ON — the fail-closed
     * posture. A dotted-quad-looking value that is NOT valid IPv4 (an octet &gt; 255, or a leading
     * zero a resolver may read as octal) is ambiguous in exactly that way, so it falls to hostname
     * verification too (code review 2026-08-27): treating {@code 999.1.2.3} as a literal would
     * silently DISABLE endpoint identification for what the resolver treats as a DNS name.
     */
    static boolean isIpLiteral(String host) {
        String bare = host.startsWith("[") && host.endsWith("]")
                ? host.substring(1, host.length() - 1)
                : host;
        if (bare.contains(":")) {
            return true; // IPv6 literal (bracketed or bare)
        }
        if (!bare.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return false;
        }
        for (String octet : bare.split("\\.")) {
            if (Integer.parseInt(octet) > 255
                    || (octet.length() > 1 && octet.charAt(0) == '0')) {
                return false; // not an IP literal the JDK would parse — treat as a hostname (verify ON)
            }
        }
        return true;
    }

    /** The per-cell listener material bundle (cert+key, and the REQUIRE-side store in Mode C). */
    private record SslMaterial(
            ProxyCompanionProperties.ServerCert serverCert,
            ProxyCompanionProperties.@Nullable TrustStore trustStore,
            String prefix) {
    }
}
