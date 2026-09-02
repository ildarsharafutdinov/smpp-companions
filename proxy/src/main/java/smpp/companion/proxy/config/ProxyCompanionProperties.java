package smpp.companion.proxy.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import smpp.companion.codec.framer.SmppFrame;

/**
 * Bound from {@code companion.*} (AD-17). The role&times;mode cell is encoded STRUCTURALLY in the
 * property path: exactly one of the five mode-leaves ({@code companion.forward.mode-a},
 * {@code companion.forward.mode-c}, {@code companion.reverse.mode-a}, {@code companion.reverse.mode-b},
 * {@code companion.reverse.mode-c}) must be populated at startup. The class-level
 * {@link ValidCompanionConfig} constraint enforces single-branch selection (AD-17 "one instance = one
 * role + one mode, mutually exclusive") and then deep-validates the selected branch. forward&times;B is
 * forbidden, so no {@code companion.forward.mode-b} node exists (SEC-051 is structural, not a runtime
 * check).
 *
 * <p>Common inputs (all cells) live at the root: the AD-34 {@code companion.tls.*} defaults, the
 * {@code companion.bind.*} port, and the AD-30 {@code companion.memory.*} inputs (defaulted in
 * application.yml). Each branch record declares ONLY the fields its cell needs, so {@code @NotNull}
 * maps directly to "required for this cell" and {@code @Nullable} to "optional" &mdash; nullability now
 * corresponds to optionality by construction. {@code max-frame} / {@code max-command-length} are
 * <b>not</b> config keys &mdash; they ARE {@link SmppFrame#MAX_COMMAND_LENGTH}, referenced directly
 * (RELAY-026 &mdash; one named value, nothing to drift).
 *
 * <p>{@code ignoreUnknownFields = false} makes a typo'd {@code companion.*} key (including a stray
 * forward.mode-b path) fail loudly at bind time &mdash; fail-closed (AD-11).
 */
@ConfigurationProperties(value = "companion", ignoreUnknownFields = false)
@Validated
@ValidCompanionConfig
public record ProxyCompanionProperties(

        @NotNull(message = "companion.bind.* is required — refusing to start.")
        @Valid Bind bind,

        @NotNull(message = "companion.memory.* is required — refusing to start (AD-30).")
        @Valid Memory memory,

        @NotNull(message = "companion.tls.* is required — refusing to start (AD-34).")
        @Valid Tls tls,

        @Valid @Nullable Forward forward,

        @Valid @Nullable Reverse reverse,

        @Valid @Nullable Metrics metrics
) {

    /**
     * Enforces AD-17 single-branch selection at CONSTRUCTION (binding) time: exactly one of the five
     * mode-leaves must be populated; 0 or &gt;1 throws, failing context refresh before Bean Validation
     * runs. This is the primary gate; the class-level {@link ValidCompanionConfig} validator is the
     * second line of defense and additionally performs the per-branch content checks (file readability,
     * OIDC https, trust-store load, Mode B ack) that a constructor cannot express.
     */
    public ProxyCompanionProperties {
        if (forward == null && reverse == null) {
            throw new IllegalArgumentException(
                    "no companion.<role> branch is configured — exactly one is required (AD-17) — refusing to start.");
        }
        if (forward != null && reverse != null) {
            throw new IllegalArgumentException(
                    "exactly one companion.<role> branch is allowed (AD-17); found 2 — refusing to start.");
        }
    }

    /**
     * forward role container: mode A (one-way TLS) and mode C (mTLS). Mode B is forbidden (absent).
     * Binding: {@code companion.forward.mode-a}/{@code companion.forward.mode-c}.
     *
     * <p>{@code tlsContexts} is the AD-29 per-target client-cert override map ({@code id →
     * client-cert/key}, binding {@code companion.forward.tls-contexts.<id>.*}): a routing entry's
     * {@code tls-context-id} selects one; absent → the instance-level default context (the forward
     * cell's own client cert, or trust-only in Mode A). Forward-scoped because ONLY the forward
     * dials TLS ([B] topology) — reverse cells carry no routing entries and no client material.
     */
    public record Forward(
            @Valid @Nullable ForwardModeA modeA,   // companion.forward.mode-a
            @Valid @Nullable ForwardModeC modeC,   // companion.forward.mode-c
            @Valid @Nullable Map<String, ClientCert> tlsContexts   // companion.forward.tls-contexts.<id>.* (optional, AD-29)
    ) {
        public Forward {
            if (modeA == null && modeC == null) {
                throw new IllegalArgumentException(
                        "no companion.forward.<mode> branch is configured — exactly one is required (AD-17) — refusing to start.");
            }
            if (modeA != null && modeC != null) {
                throw new IllegalArgumentException(
                        "exactly one companion.forward.<mode> branch is allowed (AD-17); found 2 — refusing to start.");
            }
        }
    }

    /**
     * reverse role container: mode A (client trust store), mode B (plaintext, opt-in), mode C (mTLS).
     * Binding: {@code companion.reverse.mode-a|mode-b|mode-c}.
     */
    public record Reverse(
            @Valid @Nullable ReverseModeA modeA,   // companion.reverse.mode-a
            @Valid @Nullable ReverseModeB modeB,   // companion.reverse.mode-b
            @Valid @Nullable ReverseModeC modeC    // companion.reverse.mode-c
    ) {
        public Reverse {
            if (modeA == null && modeB == null && modeC == null) {
                throw new IllegalArgumentException(
                        "no companion.reverse.<mode> branch is configured — exactly one is required (AD-17) — refusing to start.");
            }
            int branches = 0;
            if (modeA != null) branches++;
            if (modeB != null) branches++;
            if (modeC != null) branches++;
            if (branches > 1) {
                throw new IllegalArgumentException(
                        "exactly one companion.reverse.<mode> branch is allowed (AD-17); found " + branches
                                + " — refusing to start.");
            }
        }
    }

    /**
     * forward × A (trusted leg plaintext; per-session one-way TLS dial to the reverse): client trust
     * store anchoring the reverse proxy's internet-leg server cert (SEC-096) + routing. NO OIDC — the
     * forward role is a trusted-side relay (AD-12 amended 2026-08-18: the reverse role adjudicates).
     * SMSC NOT required (SEC-097). NO server cert — under the [B] topology (2026-08-21) the REVERSE
     * holds the internet-leg TLS listener; the forward dials out per SMPP session.
     */
    public record ForwardModeA(
            @NotNull(message = "companion.forward.mode-a.trust-store is required (forward dials TLS, SEC-096) — refusing to start.")
            @Valid TrustStore trustStore,
            @NotNull(message = "companion.forward.mode-a.routing is required and must be non-empty (AD-29, SEC-058) — refusing to start.")
            @Valid List<RoutingEntry> routing
    ) {
    }

    /**
     * forward × C (trusted leg plaintext; per-session mTLS dial to the reverse): forward-A material +
     * the per-instance client cert+key presented on every dial (SEC-057/FR-AUTH-3). NO OIDC —
     * trusted-side relay (AD-12 amended 2026-08-18). NO server cert ([B] topology).
     */
    public record ForwardModeC(
            @NotNull(message = "companion.forward.mode-c.client-cert is required (forward C mTLS dial, SEC-057) — refusing to start.")
            @Valid ClientCert clientCert,
            @NotNull(message = "companion.forward.mode-c.trust-store is required (forward dials TLS, SEC-050) — refusing to start.")
            @Valid TrustStore trustStore,
            @NotNull(message = "companion.forward.mode-c.routing is required and must be non-empty (AD-29, SEC-058) — refusing to start.")
            @Valid List<RoutingEntry> routing
    ) {
    }

    /**
     * reverse × A (internet leg, one-way TLS listener): SMSC endpoint (plaintext trusted SMSC leg) +
     * the internet-leg server cert+key the listener presents (SEC-056) + OIDC — the reverse role
     * adjudicates every bind before the SMSC (AD-12 amended 2026-08-18). NO trust store — one-way
     * TLS presents a cert, it does not validate peers ([B] topology: the reverse cannot authenticate
     * the forward in Mode A; the Mode A accepted-risk entry in the spine's register governs).
     */
    public record ReverseModeA(
            @NotNull(message = "companion.reverse.mode-a.smsc is required (reverse, SEC-059) — refusing to start.")
            @Valid Smsc smsc,
            @NotNull(message = "companion.reverse.mode-a.server-cert is required (reverse internet-leg listener, SEC-056) — refusing to start.")
            @Valid ServerCert serverCert,
            @NotNull(message = "companion.reverse.mode-a.oidc is required (reverse performs OIDC, AD-12, SEC-054) — refusing to start.")
            @Valid Oidc oidc
    ) {
    }

    /**
     * reverse × B (plaintext internet leg, direct client→reverse — no forward proxy exists).
     * {@code acknowledged} MUST be true to start (SEC-052 warn+ack+start) + OIDC — the reverse still
     * adjudicates in Mode B ("plaintext + ROPC"; AD-12 amended 2026-08-18).
     */
    public record ReverseModeB(
            @NotNull(message = "companion.reverse.mode-b.smsc is required (reverse, SEC-059) — refusing to start.")
            @Valid Smsc smsc,
            boolean acknowledged,   // companion.reverse.mode-b.acknowledged — validated to be true
            @NotNull(message = "companion.reverse.mode-b.oidc is required (reverse performs OIDC, AD-12, SEC-054) — refusing to start.")
            @Valid Oidc oidc
    ) {
    }

    /**
     * reverse × C (internet leg, mTLS listener): SMSC endpoint (plaintext trusted SMSC leg) + the
     * internet-leg server cert+key (SEC-056) + trust store REQUIRE-validating the forward's
     * per-instance client cert (SEC-050, AD-13 — never WANT) + OIDC (AD-12 amended 2026-08-18).
     * NO client cert on this cell — under [B] the forward dials in and PRESENTS one.
     */
    public record ReverseModeC(
            @NotNull(message = "companion.reverse.mode-c.smsc is required (reverse, SEC-059) — refusing to start.")
            @Valid Smsc smsc,
            @NotNull(message = "companion.reverse.mode-c.server-cert is required (reverse internet-leg listener, SEC-056) — refusing to start.")
            @Valid ServerCert serverCert,
            @NotNull(message = "companion.reverse.mode-c.trust-store is required (reverse C REQUIRE, SEC-050) — refusing to start.")
            @Valid TrustStore trustStore,
            @NotNull(message = "companion.reverse.mode-c.oidc is required (reverse performs OIDC, AD-12, SEC-054) — refusing to start.")
            @Valid Oidc oidc
    ) {
    }

    // --- leaf value records (reused across branches) -------------------------------------

    /**
     * AD-34 pinned TLS defaults; the floor (TLS 1.2 min) + cipher intersection are validated at bind
     * time. Policy only — applies to every TLS context both roles build; the per-target client-cert
     * override map lives on the forward role ({@code Forward.tlsContexts}, AD-29).
     */
    public record Tls(
            List<String> protocols,          // companion.tls.protocols
            List<String> tls12CipherSuites,  // companion.tls.tls12-cipher-suites (relaxed binding)
            List<String> tls13CipherSuites   // companion.tls.tls13-cipher-suites
    ) {
    }

    /**
     * OIDC provider (the reverse role performs OIDC &mdash; sole enforcement point before the SMSC;
     * AD-12 amended 2026-08-18) &mdash; the Epic-3 ROPC adapter's whole
     * config surface (Story 3.2 AC8). The old {@code client-credential-path} key is REPLACED by the
     * required {@code client-secret-path} &mdash; a pre-release rename, no transition shim.
     * (2026-08-19: the optional RFC 8705 {@code client-mtls-keystore} arm was removed pre-release
     * &mdash; {@code client_secret} is the sole provider client auth.)
     *
     * <p><b>Budget keys are REQUIRED</b> ({@code timeout} and {@code max-in-flight} are
     * {@code @NotNull}; there is NO compact-ctor normalization and no
     * default constants). <b>Structural note &mdash; why branch keys cannot carry live yml
     * defaults:</b> the yml branch templates are commented, and any uncommented
     * {@code companion.<role>.<mode>} key binds that branch for EVERY deployment, so every other
     * cell's boot refuses ("found 2", AD-17 single-branch). yml is therefore a DOCUMENTATION
     * surface: the reverse template carries the documented values ({@code 4s} / {@code 64})
     * an operator copies when uncommenting, while a hand-rolled config that omits a
     * budget key refuses startup &mdash; the {@code companion.bind.adjudication-deadline} pattern
     * (runner/test configs state them explicitly; runner boots do not load application.yml).
     * (2026-08-27, Story 3.4 T2: a third former budget key &mdash; the key-cache TTL &mdash; was
     * REMOVED with local JWT verification and the cached provider key set; a config still carrying
     * the retired key refuses startup under {@code ignoreUnknownFields = false}, and the binder's
     * unknown-field error names it &mdash; deliberately loud.)
     *
     * <p><b>Operator guidance &mdash; JWT-only adjudication (Story 3.4 T1, 2026-08-27):</b> the
     * provider's token endpoint must issue JWT access tokens. A non-JWT (opaque) token response
     * denies fail-closed ({@code DenyIndeterminate} + a WARN naming the policy); the opaque-token
     * second-arm fallback this config surface once documented was removed with the arm.
     * Remediation: configure the client/realm to issue JWT access tokens (the pinned Keycloak
     * &ge;26.7.0 issues JWTs by default).
     *
     * @param providerUrl the OIDC provider's base URL as a {@link URI} ({@code https} + a host required,
     *        SEC-053/054 &mdash; checked by the validator; a string that is not a URI at all refuses at
     *        BIND time, conversion failure); the token endpoint is DERIVED from it
     *        ({@code <provider-url>/protocol/openid-connect/token} &mdash; since Story 3.4 T9,
     *        2026-08-29, when the startup discovery probe was removed; no per-endpoint override keys)
     *        &mdash; so it MUST be the Keycloak REALM base (e.g.
     *        {@code https://idp.example.com/realms/smpp-companions}). Operator contract (the
     *        application.yml policy block is the mirror): Direct Access Grants (the password grant)
     *        is PER-CLIENT and OFF by default since Keycloak 26.2 &mdash; enable it on the client,
     *        or every bind denies fail-closed at first bind (AC2 unchanged, plus a starred operator
     *        WARN naming the derived endpoint and this URL). The compact constructor strips exactly
     *        one trailing {@code '/'} so the token-path join never doubles a slash (canonicalization
     *        only &mdash; no value is ever invented; the amendment-1 no-defaulting rule concerns the
     *        budget keys).
     * @param clientId the OAuth {@code client_id} the proxy authenticates as toward the provider
     *        (AD-12).
     * @param clientSecretPath file path of the OAuth {@code client_secret} (AD-18 &mdash; a path,
     *        never an inline value) &mdash; the sole provider client auth, required.
     * @param trustStore the dedicated IdP trust store (AD-13/AD-26: never JDK {@code cacerts});
     *        file existence/readability at bind time &mdash; the full 5-state PKIX load is the T2+
     *        adapter's SSLContext build (fail-closed bean-init refusal), not the config validator.
     * @param timeout the per-call HTTP budget for one provider round trip (the token endpoint).
     *        NOT validator-enforced: the inclusive window [2s, 5s] (PERF-3) and the
     *        {@code <= companion.bind.adjudication-deadline} relation are an OPERATOR CONTRACT
     *        documented in application.yml (the OIDC_TIMEOUT comment) &mdash; the per-call budget
     *        must fit inside the whole-adjudication budget the relay hands the verifier. Required
     *        key; the yml reverse template documents {@code 4s} (matching the adjudication-deadline
     *        default) &mdash; there is no in-record default.
     * @param maxInFlight the admission cap on CONCURRENT bind adjudications (AD-28(4)). The adapter
     *        owns a single bounded virtual-thread executor of exactly this capacity, guarded by an
     *        admission semaphore: each adjudication holds one permit for its whole lifetime, and a
     *        bind arriving when all permits are held is refused fail-closed
     *        ({@code DenyIndeterminate}) WITHOUT starting any wire call to the provider. It is a
     *        REJECTION threshold, not a queue depth &mdash; nothing waits, nothing queues (AD-4: no
     *        unbounded admission). Size it comfortably above the expected concurrent bind rate so
     *        saturation means a provider stall, not normal load. Required key; the yml reverse
     *        template documents {@code 64} &mdash; no in-record default.
     */
    public record Oidc(
            @NotNull(message = "OIDC provider-url is required (reverse performs OIDC, AD-12, SEC-054) — refusing to start.")
            URI providerUrl,                      // .provider-url (URI-typed; https + host checked by the validator, SEC-053/054)
            @NotNull(message = "OIDC client-id is required (reverse performs OIDC, AD-12) — refusing to start.")
            @NotBlank(message = "OIDC client-id must not be blank (reverse performs OIDC, AD-12) — refusing to start.")
            String clientId,                      // .client-id (@NotNull catches null, @NotBlank catches "" / "   ")
            @NotNull(message = "OIDC client-secret-path is required (AD-18, SEC-060) — refusing to start.")
            String clientSecretPath,              // .client-secret-path (file path, SEC-060; sole provider client auth)
            @NotNull(message = "OIDC trust-store is required (IdP trust never falls back to cacerts, AD-13/AD-26) — refusing to start.")
            @Valid TrustStore trustStore,         // .trust-store (file-existence at bind; 5-state PKIX load at the T2+ adapter bean init)
            @NotNull(message = "OIDC timeout is required (reverse, PERF-3) — refusing to start.")
            Duration timeout,                     // .timeout (2s..5s window + <= adjudication-deadline = documented operator contract, NOT validated; yml documents 4s)
            @NotNull(message = "OIDC max-in-flight is required (reverse, AD-28(4)) — refusing to start.")
            @Min(value = 1, message = "oidc.max-in-flight must be >= 1 — refusing to start (AD-28(4)).")
            Integer maxInFlight                   // .max-in-flight (admission cap; yml documents 64 — no in-record default)
    ) {

        /**
         * Construction-time canonicalization (the 2026-08-19 T2 FIXME pass): strip exactly ONE
         * trailing {@code '/'} from the bound base URL, so the token-endpoint join
         * ({@code RopcBindCredentialVerifier}'s explicit append-after-last-segment join of its
         * {@code TOKEN_ENDPOINT_PATH} over this base &mdash; the Story 3.4 T9 derivation, which
         * replaced the 3.2-era discovery-fetched {@code token_endpoint}; plain {@code URI.resolve}
         * would drop the realm segment) never doubles a slash. The compact ctor is the only config-layer
         * place a record can rewrite its own value &mdash; a Bean-Validation constraint can only accept
         * or reject, never normalize. Null-tolerant by necessity: binding instantiates the record
         * BEFORE validation runs (an absent key, or an empty string &mdash; which converts to null for
         * non-String targets &mdash; arrives here as null), and the component {@code @NotNull} is what
         * refuses it; a ctor null guard would preempt that message with a bare NPE (the same reason
         * no other component carries one).
         */
        public Oidc {
            if (providerUrl != null) {
                String url = providerUrl.toString();
                if (url.endsWith("/")) {
                    providerUrl = URI.create(url.substring(0, url.length() - 1));
                }
            }
        }
    }

    /**
     * SMSC endpoint. Required for the reverse role (SEC-059).
     */
    public record Smsc(
            @NotNull(message = "smsc.host is required for the reverse role (SEC-059) — refusing to start.")
            String host,                          // .host
            @Min(value = 1, message = "smsc.port must be in [1,65535] — refusing to start (SEC-055).")
            @Max(value = 65535, message = "smsc.port must be in [1,65535] — refusing to start (SEC-055).")
            int port                              // .port
    ) {
    }

    /**
     * The proxy's own SMPP listener (always required) plus the bind-handshake adjudication budget.
     *
     * @param port the proxy's own SMPP listener port (SEC-055).
     * @param host the proxy's own SMPP listener bind address (F13, Story 3.3): the reverse binds its
     *        internet-leg TLS listener here (modes A/C) or its direct legacy listener (Mode B); the
     *        forward binds its trusted-leg plaintext listener. Default {@code 0.0.0.0} in
     *        {@code application.yml} (all interfaces — the pre-3.3 behavior); a loopback or
     *        interface-scoped value is the F13 hardening. Blank/absent refuses.
     * @param adjudicationDeadline the BUDGET for one bind's credential adjudication (Story 2.2 T7, owner
     *         FIXME 2026-08-15): {@code RequestContext.deadline = now + this} is what the relay hands the
     *         {@code BindCredentialVerifier} via the {@code ScopedValue} (AD-5/AD-12); the Epic-3 ROPC
     *         adapter derives its per-call timeouts from it. Default {@code 4s} in
     *         {@code application.yml} — the PERF-3-flavored bind-latency budget; the wired
     *         {@code AlwaysAllow} stand-in ignores it, and the RELAY-side timeout arm
     *         (no-hanging-socket enforcement) remains the deferred RELAY-020 slice. Positive — zero and
     *         negative refuse startup (compact-ctor guard, AD-17).
     */
    public record Bind(
            @Min(value = 1, message = "companion.bind.port must be in [1,65535] — refusing to start (SEC-055).")
            @Max(value = 65535, message = "companion.bind.port must be in [1,65535] — refusing to start (SEC-055).")
            int port,
            @NotNull(message = "companion.bind.host is required (F13 listener hardening) — refusing to start.")
            @NotBlank(message = "companion.bind.host must not be blank (F13 listener hardening) — refusing to start.")
            String host,
            @NotNull(message = "companion.bind.adjudication-deadline is required — refusing to start.")
            Duration adjudicationDeadline
    ) {

        /**
         * Fail-fast construction guard: the adjudication deadline must be a POSITIVE duration (zero and
         * negative are misconfigurations, not degenerate-but-usable budgets — a zero deadline would have
         * the verifier treat every bind as already-expired). Fires at construction (direct) and at refresh
         * (yml/args), so an invalid value refuses startup (AD-17).
         */
        public Bind {
            Objects.requireNonNull(adjudicationDeadline, "adjudicationDeadline");
            if (adjudicationDeadline.isZero() || adjudicationDeadline.isNegative()) {
                throw new IllegalArgumentException(
                        "companion.bind.adjudication-deadline must be positive — refusing to start (got "
                                + adjudicationDeadline + ")");
            }
        }
    }

    /**
     * The metrics node (Story 4.1, FR-OBS-1): the read-only Prometheus endpoint's configuration.
     * OPTIONAL — absent means the endpoint stays down (programmatic fixtures construct without it);
     * the shipped application.yml defaults it so production boots observable. The BIND ADDRESS IS
     * DELIBERATELY NOT A KEY: the endpoint binds the literal 127.0.0.1 — loopback IPv4 is the
     * endpoint's sole authentication, so a non-loopback exposure cannot be misconfigured into
     * existence.
     */
    public record Metrics(
            @Min(value = 1, message = "companion.metrics.port must be in [1,65535] — refusing to start.")
            @Max(value = 65535, message = "companion.metrics.port must be in [1,65535] — refusing to start.")
            int port
    ) {

        /**
         * Fail-fast construction guard: the port range must hold even for programmatic construction,
         * where the Bean Validation annotations above never fire (binder path only). Fires first at
         * binding too — same wording as the annotations, one truth (AD-17).
         */
        public Metrics {
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException(
                        "companion.metrics.port must be in [1,65535] — refusing to start (got " + port + ").");
            }
        }
    }

    /**
     * Internet-leg server cert+key (the REVERSE cells' TLS listener, [B] topology). FILE PATHS (AD-18).
     */
    public record ServerCert(
            @NotNull(message = "server-cert.cert-path is required (reverse A/C, AD-18, SEC-060) — refusing to start.")
            String certPath,                      // .cert-path
            @NotNull(message = "server-cert.key-path is required (reverse A/C, AD-18, SEC-060) — refusing to start.")
            String keyPath                        // .key-path
    ) {
    }

    /**
     * Per-instance client cert+key (the FORWARD cell's Mode C dial, and every {@code
     * forward.tls-contexts} override — FR-AUTH-3: one cert per runtime instance, never a shared
     * golden-image key). FILE PATHS (AD-18).
     */
    public record ClientCert(
            @NotNull(message = "client-cert.cert-path is required (forward C mTLS dial, AD-18, SEC-060) — refusing to start.")
            String certPath,                      // .cert-path
            @NotNull(message = "client-cert.key-path is required (forward C mTLS dial, AD-18, SEC-060) — refusing to start.")
            String keyPath                        // .key-path
    ) {
    }

    /**
     * Operator trust store. NEVER falls back to JDK cacerts (AD-13/AD-26).
     */
    public record TrustStore(
            @NotNull(message = "trust-store.path is required (AD-13/AD-26) — refusing to start.")
            String path,                          // .path
            @Nullable String password             // .password (genuinely optional; null tolerated by KeyStore.load)
    ) {
    }

    /**
     * AD-29 1:1 routing entry: a permitted system_id → the single egress target.
     */
    public record RoutingEntry(
            @NotNull(message = "routing[].system-id is required (AD-29) — refusing to start.")
            String systemId,                      // [].system-id
            @NotNull(message = "routing[].host is required (AD-29) — refusing to start.")
            String host,                          // [].host
            @Min(value = 1, message = "routing entry port must be in [1,65535] — refusing to start.")
            @Max(value = 65535, message = "routing entry port must be in [1,65535] — refusing to start.")
            int port,                             // [].port
            @Nullable String tlsContextId         // [].tls-context-id (optional, AD-29)
    ) {
    }

    /**
     * AD-30 direct-memory budget inputs ({@code MaxDirectMemorySize = SmppFrame.MAX_COMMAND_LENGTH ×
     * maxInboundDepth × concurrentPairs × safetyFactor}). The max-frame input IS the codec constant
     * ({@link SmppFrame#MAX_COMMAND_LENGTH}, RELAY-026) &mdash; referenced directly, not a config key.
     * The fourth key, {@code budget-check}, is the over-ceiling policy for the AD-30 live startup
     * self-check &mdash; NOT an input to the budget formula. Like the other {@code memory.*} inputs it
     * ships defaulted in application.yml ({@code fail}); there is deliberately no {@code @DefaultValue}
     * here &mdash; it could construct a half-defaulted record when the whole {@code memory} node is
     * absent, changing the omitted-block refusal semantics.
     */
    public record Memory(
            @Min(value = 1, message = "companion.memory.max-inbound-depth must be >= 1 — refusing to start (AD-30).")
            int maxInboundDepth,                  // companion.memory.max-inbound-depth
            @Min(value = 1, message = "companion.memory.concurrent-pairs must be >= 1 — refusing to start (AD-30).")
            int concurrentPairs,                  // companion.memory.concurrent-pairs — ALSO the F13 accepted-connection cap (every accepted connection can become a budgeted pair; one number, no separate bind.max-connections knob)
            @DecimalMin(value = "1.0", message = "companion.memory.safety-factor must be a finite number (>= 1.0) — refusing to start (AD-30).")
            double safetyFactor,                  // companion.memory.safety-factor
            BudgetCheck budgetCheck               // companion.memory.budget-check — FAIL default ships in application.yml
    ) {

        /**
         * Over-ceiling policy for the AD-30 live startup self-check
         * ({@code companion.memory.budget-check}). The default ({@link #FAIL}) ships in
         * application.yml; the check treats any non-{@link #WARN} value &mdash; including a defensively
         * null bind from a yml-less context &mdash; as FAIL, so the fail-closed posture holds even
         * outside the shipped default. There is deliberately no value that skips the check itself (it
         * always computes and compares; only the over-budget severity is tunable).
         */
        public enum BudgetCheck {
            /** Refuse to start when the budget exceeds the live ceiling (AD-17 fail-fast) — the default. */
            FAIL,
            /** Emit the loud over-budget accepted-risk banner and start anyway (the Mode B pattern, AD-17/SEC-052). */
            WARN
        }
    }
}
