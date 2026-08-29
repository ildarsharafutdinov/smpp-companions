package smpp.companion.proxy.config;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;

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
import java.util.function.Function;
import java.util.stream.Stream;
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
 * from the runtime matrix. Story 3.2 adds the OIDC <em>path</em> checks (AC8): file
 * existence/readability for {@code client-secret-path} and the IdP {@code trust-store.path}.
 * Structural conformance of the oidc node (requiredness, ranges) is carried by annotations; deeper
 * material checks (the trust-store PKIX load) happen when the Epic-3 adapter builds its SSLContext
 * &mdash; a bad store refuses startup at bean init, fail-closed. The {@code oidc.timeout} window
 * (2s&ndash;5s, PERF-3) is deliberately NOT validated here &mdash; it is an operator contract
 * documented in application.yml.
 *
 * <p><b>Pre-pass and why most defensive null guards were deleted.</b> {@link #isValid} first validates
 * each non-null nested record (bind/forward/memory/reverse/tls) with a cached {@link Validator}, which
 * cascades {@code @Valid} and surfaces every NESTED {@code @NotNull}/{@code @Min}/{@code @Max} violation.
 * It registers those violations and bails, so every deep-check helper below receives only fully
 * conformant nested records &mdash; the per-object null guards that previously shadowed field-level
 * {@code @NotNull} (the {@code if (smsc == null) return;} / {@code if (oidc == null) return;} / etc.)
 * and their {@code @Nullable} parameters were removed. That also clears IntelliJ's {@code DataFlowIssue}
 * "always true" warnings on the surviving guards: under the package's {@code @NullMarked}, dropping the
 * annotation makes the parameter definitely non-null.
 *
 * <p>Two categories of null guard <em>remain</em>, because the pre-pass cannot cover them:
 * <ol>
 *   <li><b>Root-level {@code @NotNull} blind spot.</b> The pre-pass validates each nested record IN
 *       ISOLATION (never the root &mdash; validating the root would recurse into this class-level
 *       constraint). {@code ProxyCompanionProperties.tls} and {@code .memory} carry root-component
 *       {@code @NotNull}, so an entirely omitted {@code companion.tls.*} / {@code companion.memory.*}
 *       block reaches {@code validateTls} / {@code validateMemoryInputs} as {@code null}; the guards
 *       there emit the clean AD-34/AD-30 "is required" message rather than an NPE (covered by
 *       {@code omittedTlsBlockRefusesCleanly} / {@code omittedMemoryBlockRefusesCleanly}).</li>
 *   <li><b>Content invariants no annotation expresses.</b> Blank-but-non-null strings (no field is
 *       {@code @NotBlank}, only {@code @NotNull}), {@code List.isEmpty()} (an empty list passes
 *       {@code @NotNull}), a null element inside a routing list ({@code @Valid} skips null list elements
 *       per the BV spec), a duplicate {@code system_id} (AD-29 allow-list), a non-HTTPS OIDC URL
 *       (SEC-053), a non-finite {@code safetyFactor} (+Infinity slips {@code @DecimalMin}; NaN is rejected by it), plus the
 *       unconditional TLS floor (SEC-061) and the AD-34 cipher/protocol intersection. The {@code Tls}
 *       record carries NO field annotations, so its list fields can bind {@code null} &mdash; those null
 *       guards stay too.</li>
 * </ol>
 *
 * <p>Field-level {@code @NotNull}/{@code @Min}/{@code @Max} (cascaded via {@code @Valid}) handle
 * per-field presence/range &mdash; and, surfaced by the pre-pass, now authoritatively carry the SEC id
 * for the absent/out-of-range case (SEC-054 OIDC url, SEC-055 ports, SEC-059 smsc host, SEC-060 secret
 * paths). The compact constructors handle single-branch selection; this constraint handles what neither
 * can express (filesystem/content checks + TLS/cipher/finite guards). Fired by {@code @Validated} at bind
 * time &rarr; non-zero startup exit on any violation.
 *
 * <p>Story 3.3 ([B] re-shape) adds: the forward cells' trust-store/client-cert checks, and the
 * routing entry {@code tls-context-id} &rarr; {@code companion.forward.tls-contexts} reference
 * check (SEC-098). The F13 accepted-connection cap needs no guard here — it IS {@code
 * companion.memory.concurrent-pairs} (one number; the acceptor reads the budget input directly).
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

    /**
     * Protocols below the AD-34 TLS 1.2 floor (SEC-061), upper-cased for case-insensitive matching.
     */
    private static final Set<String> BELOW_TLS_1_2 = Set.of("SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1");

    /**
     * Cached, thread-safe {@link Validator} used by the pre-pass. Built once per class-loader: the BV
     * spec (&sect;5.6) requires {@link Validator} be thread-safe, and building a
     * {@link jakarta.validation.ValidatorFactory} is expensive (classpath scan). The pure-HV
     * direct-validate test path ({@code sec058_emptyRoutingListRefuses}) builds its own factory and lets
     * Hibernate Validator reflect this class &mdash; class-load initializes {@code VALIDATOR} before
     * {@link #isValid} runs, and the pre-pass never recurses (nested records do not carry
     * {@code @ValidCompanionConfig}).
     */
    private static final Validator VALIDATOR =
            Validation.buildDefaultValidatorFactory().getValidator();

    @Override
    public boolean isValid(ProxyCompanionProperties props, ConstraintValidatorContext context) {
        // Pre-pass: validate each non-null nested record IN ISOLATION (never the root — that would recurse
        // into this class constraint). ofNullable drops the absent forward/reverse branch (genuinely
        // optional at the type level). Root-level @NotNull on bind/memory/tls is NOT covered here → those
        // guards live on as the deep-check null guards in validateTls/validateMemoryInputs.
        List<ConstraintViolation<Object>> prePassViolations = Stream.of(
                        Stream.<Object>ofNullable(props.bind()),
                        Stream.<Object>ofNullable(props.forward()),
                        Stream.<Object>ofNullable(props.memory()),
                        Stream.<Object>ofNullable(props.reverse()),
                        Stream.<Object>ofNullable(props.tls()))
                .flatMap(Function.identity())
                .flatMap(bean -> VALIDATOR.validate(bean).stream())
                .toList();
        if (!prePassViolations.isEmpty()) {
            // Bail with the specific field messages (not the generic default). The deep checks are skipped:
            // they would be NPE-prone / noisy on a partially-bound config. The outer Spring validate(props)
            // pass also surfaces these via @Valid cascade, so a message may appear twice — cosmetic only.
            context.disableDefaultConstraintViolation();
            for (ConstraintViolation<Object> cv : prePassViolations) {
                context.buildConstraintViolationWithTemplate(cv.getMessage()).addConstraintViolation();
            }
            return false;
        }
        List<String> invariantViolations = new ArrayList<>();
        validateBranch(props, invariantViolations);
        validateTls(props.tls(), invariantViolations);
        validateMemoryInputs(props.memory(), invariantViolations);
        if (invariantViolations.isEmpty()) {
            return true; // Mode B warning is emitted post-refresh by CompanionModeBWarning (not here).
        }
        context.disableDefaultConstraintViolation();
        for (String message : invariantViolations) {
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
        // AD-29 per-target contexts available to routing entries — FORWARD-scoped (Story 3.3 review
        // rework: only the forward dials TLS): an absent map leaves it empty, so a routing entry then
        // has NO valid tls-context-id and SEC-098 refuses the boot.
        Set<String> contextIds = (fwd == null || fwd.tlsContexts() == null)
                ? Set.of()
                : fwd.tlsContexts().keySet();
        if (fma != null) {
            validateForwardModeA(fma, contextIds, v);
        }
        if (fmc != null) {
            validateForwardModeC(fmc, contextIds, v);
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

    private void validateForwardModeA(ProxyCompanionProperties.ForwardModeA ma, Set<String> contextIds,
                                      List<String> v) {
        String prefix = "companion.forward.mode-a";
        // SEC-096: the forward's TLS client validates the reverse's internet-leg server cert against
        // this store (the [B] re-shape, Story 3.3) — full AD-13 depth, never cacerts.
        requireTrustStore(ma.trustStore(), prefix + ".trust-store", v);
        requireRouting(ma.routing(), contextIds, prefix + ".routing", v);
        // SEC-097 (positive): forward+A does NOT require an SMSC endpoint — intentionally no SMSC check.
        // NO OIDC check: the forward role is a trusted-side relay (AD-12 amended 2026-08-18 — the
        // reverse role adjudicates); the forward cells carry no oidc node at all.
    }

    private void validateForwardModeC(ProxyCompanionProperties.ForwardModeC mc, Set<String> contextIds,
                                      List<String> v) {
        String prefix = "companion.forward.mode-c";
        requireClientCert(mc.clientCert(), prefix + ".client-cert", v); // SEC-057: the per-instance dial cert.
        requireTrustStore(mc.trustStore(), prefix + ".trust-store", v); // SEC-050: full AD-13 depth.
        requireRouting(mc.routing(), contextIds, prefix + ".routing", v);
    }

    private void validateReverseModeA(ProxyCompanionProperties.ReverseModeA ma, List<String> v) {
        String prefix = "companion.reverse.mode-a";
        requireSmsc(ma.smsc(), prefix + ".smsc", v);         // SEC-059: reverse requires the SMSC endpoint.
        requireServerCert(ma.serverCert(), prefix + ".server-cert", v); // SEC-056: internet-leg listener material.
        requireOidc(ma.oidc(), prefix + ".oidc", v);         // AD-12 amended: the reverse adjudicates.
        // NO trust store on reverse+A: one-way TLS PRESENTS a cert, it does not validate peers. The
        // [B] Mode A accepted-risk entry (spine register) owns that posture.
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
        requireOidc(mb.oidc(), prefix + ".oidc", v);         // "plaintext + ROPC": Mode B still adjudicates.
    }

    private void validateReverseModeC(ProxyCompanionProperties.ReverseModeC mc, List<String> v) {
        String prefix = "companion.reverse.mode-c";
        requireSmsc(mc.smsc(), prefix + ".smsc", v);
        requireServerCert(mc.serverCert(), prefix + ".server-cert", v); // SEC-056: internet-leg listener material.
        requireTrustStore(mc.trustStore(), prefix + ".trust-store", v); // SEC-050: the REQUIRE-side anchor.
        requireOidc(mc.oidc(), prefix + ".oidc", v);         // AD-12 amended: the reverse adjudicates.
    }

    /**
     * The reverse cells' internet-leg listener cert+key (SEC-056, the [B] re-shape): file readability
     * here; PEM/key parseability is the TLS factory's eager bean-init load (fail-closed).
     */
    private void requireServerCert(ProxyCompanionProperties.ServerCert serverCert, String prefix, List<String> v) {
        requireReadableFile(serverCert.certPath(), "server certificate", prefix + ".cert-path", v);
        requireReadableFile(serverCert.keyPath(), "server key", prefix + ".key-path", v);
    }

    /**
     * {@code smsc} is {@code @NotNull} on every reverse mode → guaranteed non-null by the pre-pass.
     */
    private void requireSmsc(ProxyCompanionProperties.Smsc smsc, String prefix, List<String> v) {
        if (smsc.host().isBlank()) {
            v.add(prefix + ".host is required for the reverse role — refusing to start (SEC-059).");
        }
        // smsc.port range is field-level @Min/@Max (cascaded when smsc is present).
    }

    /**
     * {@code routing} is {@code @NotNull} (but may be empty) on forward A/C → non-null by the pre-pass.
     */
    private void requireRouting(List<ProxyCompanionProperties.RoutingEntry> routing, Set<String> contextIds,
                                String prefix, List<String> v) {
        if (routing.isEmpty()) {
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
            if (entry.systemId().isBlank()) {
                v.add(prefix + "[" + index + "].system-id is required (AD-29) — refusing to start.");
            } else if (!seenSystemIds.add(entry.systemId())) {
                // AD-29: the routing table is a system_id allow-list → a duplicate id is ambiguous
                // (which egress wins is undefined until the relay lands in Epic 2). Fail closed.
                v.add(prefix + "[" + index + "].system-id=" + entry.systemId()
                        + " is duplicated in the routing table (AD-29 allow-list) — refusing to start.");
            }
            if (entry.host().isBlank()) {
                v.add(prefix + "[" + index + "].host is required (AD-29) — refusing to start.");
            }
            if (entry.tlsContextId() != null && !contextIds.contains(entry.tlsContextId())) {
                // SEC-098 (Story 3.3): a routing entry selecting an absent forward.tls-contexts key
                // would silently fall back to the instance default at dial time — fail closed instead.
                v.add(prefix + "[" + index + "].tls-context-id=" + entry.tlsContextId()
                        + " references no companion.forward.tls-contexts entry — refusing to start (SEC-098/AD-29).");
            }
            index++;
        }
    }

    /**
     * {@code oidc} is {@code @NotNull} on reverse A/B/C → guaranteed non-null by the pre-pass; its
     * own {@code @NotNull}/{@code @NotBlank}/{@code @Min}/{@code @DurationMin} components are
     * surfaced by the pre-pass the same way. This check owns the provider-url URI shape plus FILE
     * EXISTENCE only — every configured path must point at a real readable file (AD-18). Since the
     * 2026-08-19 T2 FIXME pass the component is {@link URI}-typed: a non-URI string refuses at BIND
     * time (conversion failure), and the HOST + scheme checks live HERE ({@code https://:8443},
     * {@code http://...}) — the config layer is the deferred 2.1-era scheme-only gap's final home
     * (moved out of the former discovery build, which Story 3.4 T9 removed whole, 2026-08-29).
     * Blank and absent both bind to null and are refused by the
     * component {@code @NotNull} (empty strings convert to null for non-String targets). Deeper
     * material validation is the T2+
     * adapter's job (its SSLContext build refuses startup on a bad store, fail-closed).
     */
    private void requireOidc(ProxyCompanionProperties.Oidc oidc, String prefix, List<String> v) {
        URI providerUrl = oidc.providerUrl();
        // Absent AND blank both bind to null (empty strings convert to null for non-String targets)
        // and are refused by the component @NotNull in the pre-pass — blank and absent are ONE arm
        // now, not two. This check owns the URI SHAPE only: host, then scheme.
        if (providerUrl.getHost() == null || providerUrl.getHost().isBlank()) {
            v.add(prefix + ".provider-url=" + providerUrl + " has no host (scheme://host[:port]/... required)"
                    + " — refusing to start (SEC-053/054).");
        } else if (!"https".equalsIgnoreCase(providerUrl.getScheme())) {
            v.add(prefix + ".provider-url must use the https scheme (AD-12/SEC-3) — refusing to start (SEC-053).");
        }
        requireReadableFile(oidc.clientSecretPath(), "OIDC client secret", prefix + ".client-secret-path", v);
        requireReadableFile(oidc.trustStore().path(), "IdP trust store", prefix + ".trust-store.path", v);
    }

    /**
     * {@code clientCert} is {@code @NotNull} on reverse C → guaranteed non-null by the pre-pass.
     */
    private void requireClientCert(ProxyCompanionProperties.ClientCert clientCert, String prefix, List<String> v) {
        requireReadableFile(clientCert.certPath(), "client certificate", prefix + ".cert-path", v);
        requireReadableFile(clientCert.keyPath(), "client key", prefix + ".key-path", v);
    }

    /**
     * All callers pass a {@code @NotNull} path (server/client cert+key, OIDC credential) → non-null by the
     * pre-pass. The blank / not-a-path / missing / directory / unreadable states are content checks the
     * annotations cannot express.
     */
    private void requireReadableFile(String path, String label, String key, List<String> v) {
        if (path.isBlank()) {
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

    /**
     * {@code trustStore} is {@code @NotNull} on the mode records → guaranteed non-null by the pre-pass.
     */
    private void requireTrustStore(ProxyCompanionProperties.TrustStore trustStore, String prefix, List<String> v) {
        String key = prefix + ".path";
        if (trustStore.path().isBlank()) {
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
        char[] password = (trustStore.password() == null) ? null : trustStore.password().toCharArray();
        try {
            // Empty-file guard first (SEC-050). Files.size declares a checked IOException; rather than a
            // separate untestable catch, it is handled by THIS try's load-failure handler below — a size
            // IO error on a file that already passed exists+isReadable is an extreme edge and is refused
            // cleanly either way (the dedicated "could not be sized" branch was removed as dead-in-practice).
            if (Files.size(resolved) == 0L) {
                v.add(key + "=" + trustStore.path() + " is empty (zero bytes) — refusing to start (SEC-050).");
                return;
            }
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
        // ROOT-LEVEL @NotNull blind spot: the pre-pass skips a null tls (ofNullable drops it, and the
        // @NotNull on ProxyCompanionProperties.tls is a root-component constraint the isolated-record
        // pre-pass cannot see). An omitted companion.tls.* block reaches here as null — guard it
        // (AD-17 clear-message contract; dropping would NPE on tls.protocols()).
        if (tls == null) {
            v.add("companion.tls.* is required (AD-34) — refusing to start.");
            return;
        }
        // The list accessors are typed non-null (jspecify @NullMarked) but binding can produce null for an
        // omitted list; the Tls record carries NO field annotations, so the pre-pass cannot guarantee
        // them — pass through @Nullable params so the guards below are real, not redundant.
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
        // An empty configured set is caught by the intersection check below (empty ∩ JDK-supported =
        // empty → fail-fast). The dedicated empty-ciphers early-return was removed as redundant — it was
        // shadowed by this intersection guard and could not be made mutation-resistant on its own.
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
            // Compiler-required: SSLContext.getInstance/init declare checked exceptions, so this catch
            // cannot be removed. On JDK 25 (no SecurityManager) those calls do not throw in practice,
            // which makes the catch impractical to mutation-test in isolation — the load-bearing
            // intersection enforcement above IS covered by the AD-34 cipher/protocol refusal tests.
            // Fail-closed: any unexpected exception here still refuses startup with an AD-34 message.
            v.add("companion.tls cipher intersection check failed (" + e.getClass().getSimpleName()
                    + ") — refusing to start (AD-34).");
        }
    }

    // --- AC5 AD-30 memory inputs (RELAY-026 constant is by construction; live self-check deferred, D1) ---

    private void validateMemoryInputs(ProxyCompanionProperties.@Nullable Memory memory, List<String> v) {
        // ROOT-LEVEL @NotNull blind spot (same as validateTls): the pre-pass skips a null memory block, so
        // an omitted companion.memory.* reaches here as null — guard it (AD-17 clear-message, AD-30).
        if (memory == null) {
            v.add("companion.memory.* is required (AD-30) — refusing to start.");
            return;
        }
        // max-frame / max-command-length ARE SmppFrame.MAX_COMMAND_LENGTH by construction (referenced
        // directly, not config keys — RELAY-026), so there is nothing to drift-check here. Only the
        // operator-tunable memory inputs need a guard beyond @Min/@DecimalMin: @DecimalMin("1.0") rejects
        // NaN and values < 1.0 but passes +Infinity (HV ranks +Infinity as >= 1.0) — reject Infinity
        // explicitly via isFinite. (NaN is already caught by @DecimalMin and surfaced via the pre-pass.)
        if (!Double.isFinite(memory.safetyFactor())) {
            v.add("companion.memory.safety-factor=" + memory.safetyFactor()
                    + " must be a finite number (>= 1.0) — refusing to start (AD-30).");
        }
    }

    // --- helpers ---------------------------------------------------------------------------
}
