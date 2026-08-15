package smpp.companion.proxy.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

import java.util.List;

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

        @Valid @Nullable Reverse reverse
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
     */
    public record Forward(
            @Valid @Nullable ForwardModeA modeA,   // companion.forward.mode-a
            @Valid @Nullable ForwardModeC modeC    // companion.forward.mode-c
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
     * forward × A: server cert+key + routing + OIDC (SMSC NOT required, SEC-097).
     */
    public record ForwardModeA(
            @NotNull(message = "companion.forward.mode-a.server-cert is required (forward A/C, SEC-056) — refusing to start.")
            @Valid ServerCert serverCert,
            @NotNull(message = "companion.forward.mode-a.routing is required and must be non-empty (AD-29, SEC-058) — refusing to start.")
            @Valid List<RoutingEntry> routing,
            @NotNull(message = "companion.forward.mode-a.oidc is required (forward performs OIDC, AD-12, SEC-054) — refusing to start.")
            @Valid Oidc oidc
    ) {
    }

    /**
     * forward × C: forward-A material + trust store (mTLS to the reverse proxy).
     */
    public record ForwardModeC(
            @NotNull(message = "companion.forward.mode-c.server-cert is required (forward A/C, SEC-056) — refusing to start.")
            @Valid ServerCert serverCert,
            @NotNull(message = "companion.forward.mode-c.routing is required and must be non-empty (AD-29, SEC-058) — refusing to start.")
            @Valid List<RoutingEntry> routing,
            @NotNull(message = "companion.forward.mode-c.oidc is required (forward performs OIDC, AD-12, SEC-054) — refusing to start.")
            @Valid Oidc oidc,
            @NotNull(message = "companion.forward.mode-c.trust-store is required (forward C mTLS, SEC-050) — refusing to start.")
            @Valid TrustStore trustStore
    ) {
    }

    /**
     * reverse × A: SMSC endpoint + client trust store (forward/SMSC server-cert anchor, SEC-096).
     */
    public record ReverseModeA(
            @NotNull(message = "companion.reverse.mode-a.smsc is required (reverse, SEC-059) — refusing to start.")
            @Valid Smsc smsc,
            @NotNull(message = "companion.reverse.mode-a.trust-store is required (reverse A, SEC-096) — refusing to start.")
            @Valid TrustStore trustStore
    ) {
    }

    /**
     * reverse × B: plaintext. {@code acknowledged} MUST be true to start (SEC-052 warn+ack+start).
     */
    public record ReverseModeB(
            @NotNull(message = "companion.reverse.mode-b.smsc is required (reverse, SEC-059) — refusing to start.")
            @Valid Smsc smsc,
            boolean acknowledged   // companion.reverse.mode-b.acknowledged — validated to be true
    ) {
    }

    /**
     * reverse × C: SMSC + client cert+key (mTLS, SEC-057) + trust store.
     */
    public record ReverseModeC(
            @NotNull(message = "companion.reverse.mode-c.smsc is required (reverse, SEC-059) — refusing to start.")
            @Valid Smsc smsc,
            @NotNull(message = "companion.reverse.mode-c.client-cert is required (reverse C mTLS, SEC-057) — refusing to start.")
            @Valid ClientCert clientCert,
            @NotNull(message = "companion.reverse.mode-c.trust-store is required (reverse C, SEC-050) — refusing to start.")
            @Valid TrustStore trustStore
    ) {
    }

    // --- leaf value records (reused across branches) -------------------------------------

    /**
     * AD-34 pinned TLS defaults; the floor (TLS 1.2 min) + cipher intersection are validated at bind time.
     */
    public record Tls(
            List<String> protocols,          // companion.tls.protocols
            List<String> tls12CipherSuites,  // companion.tls.tls12-cipher-suites (relaxed binding)
            List<String> tls13CipherSuites   // companion.tls.tls13-cipher-suites
    ) {
    }

    /**
     * OIDC provider (the forward role performs OIDC, AD-12).
     */
    public record Oidc(
            @NotNull(message = "OIDC provider-url is required (forward performs OIDC, AD-12, SEC-054) — refusing to start.")
            String providerUrl,                   // .provider-url (https required, SEC-053/054)
            @NotNull(message = "OIDC client-credential-path is required (forward, AD-18, SEC-060) — refusing to start.")
            String clientCredentialPath           // .client-credential-path (file path, SEC-060)
    ) {
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
     * SMPP bind port (the proxy's own listener; always required, SEC-055).
     */
    public record Bind(
            @Min(value = 1, message = "companion.bind.port must be in [1,65535] — refusing to start (SEC-055).")
            @Max(value = 65535, message = "companion.bind.port must be in [1,65535] — refusing to start (SEC-055).")
            int port
    ) {
    }

    /**
     * Internet-leg server cert+key (forward A/C). FILE PATHS (AD-18).
     */
    public record ServerCert(
            @NotNull(message = "server-cert.cert-path is required (forward A/C, AD-18, SEC-060) — refusing to start.")
            String certPath,                      // .cert-path
            @NotNull(message = "server-cert.key-path is required (forward A/C, AD-18, SEC-060) — refusing to start.")
            String keyPath                        // .key-path
    ) {
    }

    /**
     * Mode C client cert+key (reverse C). FILE PATHS (AD-18).
     */
    public record ClientCert(
            @NotNull(message = "client-cert.cert-path is required (reverse C mTLS, AD-18, SEC-060) — refusing to start.")
            String certPath,                      // .cert-path
            @NotNull(message = "client-cert.key-path is required (reverse C mTLS, AD-18, SEC-060) — refusing to start.")
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
            int concurrentPairs,                  // companion.memory.concurrent-pairs
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
