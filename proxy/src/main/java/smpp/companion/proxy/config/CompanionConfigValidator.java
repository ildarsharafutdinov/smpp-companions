package smpp.companion.proxy.config;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.net.ssl.SSLContext;
import org.jspecify.annotations.Nullable;

/**
 * Class-level validator (decision D4) for {@link ProxyCompanionProperties}. AD-17 single-branch
 * selection (exactly one role &times; mode) is enforced by the compact constructors at binding time, so
 * by the time this constraint runs exactly one branch is populated; this validator owns ONLY the
 * per-branch content checks that neither a constructor nor field-level {@code @NotNull} can express:
 * SEC-056/057 cert/key file readability, SEC-058 routing non-empty + per-entry, SEC-053/054 OIDC
 * https/present, SEC-059 SMSC host, SEC-050 trust-store 5-state PKIX load, SEC-052 Mode B opt-in ack,
 * plus the unconditional TLS floor + cipher intersection (AD-34/SEC-061) and the AD-30 finite-memory
 * guard. forward&times;B is enforced structurally (no forward.mode-b node) &mdash; SEC-051 is retired
 * from the runtime matrix.
 *
 * <p><b>Why the defensive null checks cannot be deleted.</b> This is a Bean Validation class-level
 * constraint, so {@code isValid} runs DURING validation &mdash; before the field-level {@code @NotNull}
 * guarantees hold. A value the type system calls non-null (jspecify {@code @NullMarked}) may still be
 * {@code null} here: binding produces {@code null} for an omitted property, and only the separately
 * evaluated {@code @NotNull} constraint then reports it. Several SEC tests rely on this &mdash; e.g.
 * SEC-059 omits {@code smsc.host}, so the bound value is {@code null} when {@code requireSmsc} runs, and
 * deleting the guard would NPE, replacing the clean SEC-059 refusal message with a stack trace. IntelliJ
 * flags these guards "always false" ({@code DataFlowIssue}); that is a false positive the analyzer cannot
 * model. The checks are kept &mdash; and IDE-warning-free &mdash; by giving each deep-check helper a
 * {@code @Nullable} parameter and guarding it inside, where the check is real rather than redundant.
 *
 * <p>Field-level {@code @NotNull}/{@code @Min}/{@code @Max} (cascaded via {@code @Valid}) handle
 * per-field presence/range; the compact constructors handle single-branch selection; this constraint
 * handles what neither can express (filesystem/content checks + TLS/cipher/finite guards). Fired by
 * {@code @Validated} at bind time &rarr; non-zero startup exit on any violation.
 *
 * <p>Mode B reverse+ack is the single non-refuse insecure posture: the validator returns valid for it,
 * and the loud plaintext startup warning is emitted <em>after</em> successful refresh by
 * {@link CompanionModeBWarning} (not here &mdash; a class-level constraint cannot see the field-level
 * failures Hibernate Validator evaluates in the same pass) &mdash; per AD-17 / SEC-052.
 *
 * <p>The validator reads the filesystem (secret files, the trust store) and a JDK-default
 * {@link SSLContext} only to <em>prove</em> the configured material is present/loadable/JDK-supported;
 * it builds no runtime TLS context (per-egress-context intersection and mTLS PKIX path stay in Epic 3).
 */
public final class CompanionConfigValidator
        implements ConstraintValidator<ValidCompanionConfig, ProxyCompanionProperties> {

    /** Protocols below the AD-34 TLS 1.2 floor (SEC-061), upper-cased for case-insensitive matching. */
    private static final Set<String> BELOW_TLS_1_2 = Set.of("SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1");

    @Override
    public boolean isValid(ProxyCompanionProperties props, ConstraintValidatorContext context) {
        List<String> violations = new ArrayList<>();
        validateBranch(props, violations);
        validateTls(props.tls(), violations);
        validateMemoryInputs(props.memory(), violations);

        if (violations.isEmpty()) {
            return true; // Mode B warning is emitted post-refresh by CompanionModeBWarning (not here).
        }
        context.disableDefaultConstraintViolation();
        for (String message : violations) {
            context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
        }
        return false;
    }

    // --- per-branch deep validation (single-branch selection is constructor-enforced) -------

    private void validateBranch(ProxyCompanionProperties p, List<String> v) {
        var fwd = p.forward();
        var rev = p.reverse();
        // AD-17 single-branch selection is enforced by the compact constructors (ProxyCompanionProperties,
        // Forward, Reverse) at binding time — exactly one role and, within it, exactly one mode — so by
        // the time this class-level constraint runs exactly one mode-leaf is populated. Deep-validate
        // that branch's content (file readability, OIDC https, trust-store load, Mode B ack): the checks
        // neither a constructor nor field-level @NotNull can express.
        var fma = (fwd != null) ? fwd.modeA() : null;
        var fmc = (fwd != null) ? fwd.modeC() : null;
        var rma = (rev != null) ? rev.modeA() : null;
        var rmb = (rev != null) ? rev.modeB() : null;
        var rmc = (rev != null) ? rev.modeC() : null;
        // Exactly one mode-leaf is populated (constructor-enforced); exactly one of these fires.
        if (fma != null) {
            validateForwardModeA(fma, v);
        }
        if (fmc != null) {
            validateForwardModeC(fmc, v);
        }
        if (rma != null) {
            validateReverseModeA(rma, v);
        }
        if (rmb != null) {
            validateReverseModeB(rmb, v);
        }
        if (rmc != null) {
            validateReverseModeC(rmc, v);
        }
    }

    private void validateForwardModeA(ProxyCompanionProperties.ForwardModeA ma, List<String> v) {
        validateForwardBase(ma.serverCert(), ma.routing(), ma.oidc(), "companion.forward.mode-a", v);
        // SEC-097 (positive): forward+A does NOT require an SMSC endpoint — intentionally no SMSC check.
    }

    private void validateForwardModeC(ProxyCompanionProperties.ForwardModeC mc, List<String> v) {
        String prefix = "companion.forward.mode-c";
        validateForwardBase(mc.serverCert(), mc.routing(), mc.oidc(), prefix, v);
        // forward+C validates the mTLS trust store at the full AD-13 depth (SEC-050).
        requireTrustStore(mc.trustStore(), prefix + ".trust-store", v);
    }

    /** Shared forward A/C content: server cert+key readability (SEC-056), routing (SEC-058), OIDC (SEC-053/054). */
    private void validateForwardBase(ProxyCompanionProperties.@Nullable ServerCert serverCert,
                                     @Nullable List<ProxyCompanionProperties.RoutingEntry> routing,
                                     ProxyCompanionProperties.@Nullable Oidc oidc,
                                     String prefix, List<String> v) {
        if (serverCert != null) {
            requireReadableFile(serverCert.certPath(), "server certificate", prefix + ".server-cert.cert-path", v);
            requireReadableFile(serverCert.keyPath(), "server key", prefix + ".server-cert.key-path", v);
        }
        requireRouting(routing, prefix + ".routing", v);
        requireOidc(oidc, prefix + ".oidc", v);
    }

    private void validateReverseModeA(ProxyCompanionProperties.ReverseModeA ma, List<String> v) {
        String prefix = "companion.reverse.mode-a";
        requireSmsc(ma.smsc(), prefix + ".smsc", v);         // SEC-059: reverse requires the SMSC endpoint.
        requireTrustStore(ma.trustStore(), prefix + ".trust-store", v); // SEC-096: forward/SMSC server-cert anchor.
    }

    private void validateReverseModeB(ProxyCompanionProperties.ReverseModeB mb, List<String> v) {
        String prefix = "companion.reverse.mode-b";
        requireSmsc(mb.smsc(), prefix + ".smsc", v);
        // SEC-052: Mode B reverse requires opt-in ack; without it refuse. With it the loud plaintext
        // warning is emitted by CompanionModeBWarning, then starts.
        if (!mb.acknowledged()) {
            v.add("companion.reverse.mode-b (plaintext) requires explicit opt-in ("
                    + prefix + ".acknowledged=true) — refusing to start (SEC-052/AD-17).");
        }
    }

    private void validateReverseModeC(ProxyCompanionProperties.ReverseModeC mc, List<String> v) {
        String prefix = "companion.reverse.mode-c";
        requireSmsc(mc.smsc(), prefix + ".smsc", v);
        requireClientCert(mc.clientCert(), prefix + ".client-cert", v); // SEC-057: reverse+C client cert+key.
        requireTrustStore(mc.trustStore(), prefix + ".trust-store", v);
    }

    private void requireSmsc(ProxyCompanionProperties.@Nullable Smsc smsc, String prefix, List<String> v) {
        if (smsc == null) {
            return; // field-level @NotNull on smsc reports the absent block.
        }
        if (isNullOrBlank(smsc.host())) {
            v.add(prefix + ".host is required for the reverse role — refusing to start (SEC-059).");
        }
        // smsc.port range is field-level @Min/@Max (cascaded when smsc is present).
    }

    private void requireRouting(@Nullable List<ProxyCompanionProperties.RoutingEntry> routing, String prefix, List<String> v) {
        if (routing == null || routing.isEmpty()) {
            v.add(prefix + " is required and must be non-empty for the forward role (AD-29 1:1; "
                    + "no default route per AD-11) — refusing to start (SEC-058).");
            return;
        }
        int index = 0;
        Set<String> seenSystemIds = new HashSet<>();
        for (ProxyCompanionProperties.RoutingEntry entry : routing) {
            if (entry == null) {
                // @Valid on a List skips null elements (Bean Validation spec), so a null entry bypasses
                // the per-field @NotNull guards — reject it explicitly here.
                v.add(prefix + "[" + index + "] is null (AD-29) — refusing to start.");
                index++;
                continue;
            }
            if (isNullOrBlank(entry.systemId())) {
                v.add(prefix + "[" + index + "].system-id is required (AD-29) — refusing to start.");
            } else if (!seenSystemIds.add(entry.systemId())) {
                // AD-29: the routing table is a system_id allow-list → a duplicate id is ambiguous
                // (which egress wins is undefined until the relay lands in Epic 2). Fail closed.
                v.add(prefix + "[" + index + "].system-id=" + entry.systemId()
                        + " is duplicated in the routing table (AD-29 allow-list) — refusing to start.");
            }
            if (isNullOrBlank(entry.host())) {
                v.add(prefix + "[" + index + "].host is required (AD-29) — refusing to start.");
            }
            index++;
        }
    }

    private void requireOidc(ProxyCompanionProperties.@Nullable Oidc oidc, String prefix, List<String> v) {
        if (oidc == null) {
            return; // field-level @NotNull on oidc reports the absent block.
        }
        String providerUrl = oidc.providerUrl();
        if (isNullOrBlank(providerUrl)) {
            v.add(prefix + ".provider-url is required for the forward role (AD-12) — refusing to start (SEC-054).");
        } else if (!isHttps(providerUrl)) {
            v.add(prefix + ".provider-url must use the https scheme (AD-12/SEC-3) — refusing to start (SEC-053).");
        }
        requireReadableFile(oidc.clientCredentialPath(), "OIDC client credential", prefix + ".client-credential-path", v);
    }

    private void requireClientCert(ProxyCompanionProperties.@Nullable ClientCert clientCert, String prefix, List<String> v) {
        if (clientCert == null) {
            return; // field-level @NotNull on client-cert reports the absent block.
        }
        requireReadableFile(clientCert.certPath(), "client certificate", prefix + ".cert-path", v);
        requireReadableFile(clientCert.keyPath(), "client key", prefix + ".key-path", v);
    }

    private void requireReadableFile(@Nullable String path, String label, String key, List<String> v) {
        if (isNullOrBlank(path)) {
            v.add(key + " is required (" + label + " file path, AD-18) — refusing to start (SEC-060).");
            return;
        }
        Path resolved;
        try {
            resolved = Path.of(path);
        } catch (InvalidPathException e) {
            v.add(key + "=" + path + " is not a valid path (" + e.getClass().getSimpleName()
                    + ") — refusing to start (SEC-060/AD-18).");
            return;
        }
        if (!Files.exists(resolved)) {
            v.add(key + "=" + path + " does not exist (" + label + " file missing) — refusing to start (SEC-060/AD-18).");
        } else if (Files.isDirectory(resolved)) {
            v.add(key + "=" + path + " is a directory, not a file (" + label
                    + ") — refusing to start (SEC-060/AD-18).");
        } else if (!Files.isReadable(resolved)) {
            v.add(key + "=" + path + " is not readable (" + label + " file permissions) — refusing to start (SEC-060/AD-18).");
        }
    }

    // --- SEC-050 trust-store 5-state (decision D5: real KeyStore.load PKIX validation) ---------

    private void requireTrustStore(ProxyCompanionProperties.@Nullable TrustStore trustStore, String prefix, List<String> v) {
        String key = prefix + ".path";
        if (trustStore == null || isNullOrBlank(trustStore.path())) {
            v.add(key + " is required (trust store never falls back to cacerts, AD-13/AD-26) — refusing to start (SEC-050).");
            return;
        }
        Path resolved;
        try {
            resolved = Path.of(trustStore.path());
        } catch (InvalidPathException e) {
            v.add(key + "=" + trustStore.path() + " is not a valid path (" + e.getClass().getSimpleName()
                    + ") — refusing to start (SEC-050).");
            return;
        }
        if (!Files.exists(resolved)) {
            v.add(key + "=" + trustStore.path() + " does not exist — refusing to start (SEC-050).");
            return;
        }
        if (!Files.isReadable(resolved)) {
            v.add(key + "=" + trustStore.path() + " is not readable — refusing to start (SEC-060/SEC-050).");
            return;
        }
        try {
            if (Files.size(resolved) == 0L) {
                v.add(key + "=" + trustStore.path() + " is empty (zero bytes) — refusing to start (SEC-050).");
                return;
            }
        } catch (IOException e) {
            v.add(key + "=" + trustStore.path() + " could not be sized (IO error) — refusing to start (SEC-050).");
            return;
        }
        char[] password = (trustStore.password() == null) ? null : trustStore.password().toCharArray();
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream in = Files.newInputStream(resolved)) {
                keyStore.load(in, password); // wrong-format / wrong-password throw here.
            }
            int trusted = 0;
            for (String alias : Collections.list(keyStore.aliases())) {
                if (keyStore.isCertificateEntry(alias)) {
                    trusted++;
                }
            }
            if (trusted == 0) {
                v.add(key + "=" + trustStore.path() + " contains zero trustedCertEntry entries — refusing to start (SEC-050/AD-13).");
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            v.add(key + "=" + trustStore.path() + " is not a valid trust store (" + e.getClass().getSimpleName()
                    + ": " + e.getMessage() + "). PKCS12 is expected on JDK 9+ (JKS is not supported in 1.3 "
                    + "— see deferred-work) — refusing to start (SEC-050/AD-13).");
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0'); // secret hygiene (AD-10): zeroize the password buffer.
            }
        }
    }

    // --- AC2 TLS floor (SEC-061) + cipher intersection (AD-34, decision D2) -------------------

    private void validateTls(ProxyCompanionProperties.@Nullable Tls tls, List<String> v) {
        // Class-level constraint runs before the field-level @NotNull on `tls` holds (see class javadoc),
        // so a missing companion.tls.* block reaches here as null — guard it (AD-17 clear-message contract).
        if (tls == null) {
            v.add("companion.tls.* is required (AD-34) — refusing to start.");
            return;
        }
        // The list accessors are typed non-null (jspecify @NullMarked) but binding can produce null for an
        // omitted list; pass them through @Nullable params so the guards below are real, not redundant.
        validateTlsContent(tls.protocols(), tls.tls12CipherSuites(), tls.tls13CipherSuites(), v);
    }

    private void validateTlsContent(@Nullable List<String> protocols,
                                    @Nullable List<String> tls12CipherSuites,
                                    @Nullable List<String> tls13CipherSuites,
                                    List<String> v) {
        // SEC-061 TLS floor (case-insensitive) + non-empty/blank-protocol guards.
        if (protocols == null || protocols.isEmpty()) {
            v.add("companion.tls.protocols is required and must be non-empty (AD-34) — refusing to start.");
        } else {
            for (String protocol : protocols) {
                if (protocol.isBlank()) {
                    v.add("companion.tls.protocols contains a null/blank entry (AD-34) — refusing to start.");
                    break;
                }
                if (BELOW_TLS_1_2.contains(protocol.toUpperCase(Locale.ROOT))) {
                    v.add("companion.tls.protocols contains a sub-TLS-1.2 protocol (" + protocol
                            + "); the TLS floor is 1.2 (AD-34) — refusing to start (SEC-061).");
                    break;
                }
            }
        }
        // AD-34 cipher intersection (decision D2) + protocol JDK-support (AC2 "cipher/protocol intersection").
        Set<String> configured = new HashSet<>();
        if (tls12CipherSuites != null) {
            configured.addAll(tls12CipherSuites);
        }
        if (tls13CipherSuites != null) {
            configured.addAll(tls13CipherSuites);
        }
        if (configured.isEmpty()) {
            v.add("companion.tls cipher suites are empty — refusing to start (AD-34).");
            return;
        }
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null); // the JDK-default context (proves the set is JDK-supported).
            Set<String> supported = new HashSet<>(Arrays.asList(sslContext.getSocketFactory().getSupportedCipherSuites()));
            configured.retainAll(supported);
            if (configured.isEmpty()) {
                v.add("companion.tls cipher suites have an empty intersection with the JDK-default SSLContext "
                        + "supported suites — refusing to start (AD-34). Per-egress-context intersection is Epic 3.");
            }
            // The SEC-061 floor only rejects sub-1.2 names; a bogus future name (e.g. TLSv9.99) would slip it,
            // so also confirm every configured protocol is JDK-supported (AD-34).
            Set<String> supportedProtocols =
                    new HashSet<>(Arrays.asList(sslContext.getSupportedSSLParameters().getProtocols()));
            if (protocols != null) {
                for (String protocol : protocols) {
                    if (!supportedProtocols.contains(protocol)) {
                        v.add("companion.tls.protocols entry " + protocol
                                + " is not supported by the JDK-default SSLContext — refusing to start (AD-34).");
                    }
                }
            }
        } catch (Exception e) {
            v.add("companion.tls cipher intersection check failed (" + e.getClass().getSimpleName()
                    + ") — refusing to start (AD-34).");
        }
    }

    // --- AC5 AD-30 memory inputs (RELAY-026 constant is by construction; live self-check deferred, D1) ---

    private void validateMemoryInputs(ProxyCompanionProperties.@Nullable Memory memory, List<String> v) {
        // Same class-constraint-runs-before-@NotNull caveat as validateTls (see class javadoc): a missing
        // companion.memory.* block reaches here as null — guard it (AD-17 clear-message contract, AD-30).
        if (memory == null) {
            v.add("companion.memory.* is required (AD-30) — refusing to start.");
            return;
        }
        // max-frame / max-command-length ARE SmppFrame.MAX_COMMAND_LENGTH by construction (referenced
        // directly, not config keys — RELAY-026), so there is nothing to drift-check here. Only the
        // operator-tunable memory inputs need a guard: @DecimalMin("1.0") on safetyFactor does not reject
        // NaN (Hibernate Validator's Double.compare ranks NaN as large) — reject non-finite explicitly.
        if (!Double.isFinite(memory.safetyFactor())) {
            v.add("companion.memory.safety-factor=" + memory.safetyFactor()
                    + " must be a finite number (>= 1.0) — refusing to start (AD-30).");
        }
    }

    // --- helpers ---------------------------------------------------------------------------

    private static boolean isNullOrBlank(@Nullable String s) {
        return s == null || s.isBlank();
    }

    private static boolean isHttps(String url) {
        try {
            String scheme = URI.create(url).getScheme();
            return "https".equalsIgnoreCase(scheme);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
