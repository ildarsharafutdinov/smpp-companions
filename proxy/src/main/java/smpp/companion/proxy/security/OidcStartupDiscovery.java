package smpp.companion.proxy.security;

import com.nimbusds.jose.util.JSONObjectUtils;

import lombok.extern.slf4j.Slf4j;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.net.ssl.SSLParameters;

import smpp.companion.proxy.config.ProxyCompanionProperties;

/**
 * Story 3.2 T2 (AC7) — the hard-required startup OIDC discovery probe (AD-12). Once per boot, at
 * bean initialization, every <b>reverse</b> cell GETs
 * {@code <provider-url>/.well-known/openid-configuration} over the real IdP TLS link
 * ({@link IdpSslContextFactory}'s context + AD-34-intersected parameters) and REFUSES startup on
 * any failure &mdash; non-200, unparseable body, missing endpoint field, unreachable provider.
 * (The provider URL's SHAPE &mdash; URI-parseable, https, hostful &mdash; is refused one layer
 * earlier, at bind time, by {@code CompanionConfigValidator}: the 2026-08-19 T2 FIXME pass made
 * the component {@link URI}-typed and moved the hostless/scheme checks into the config layer.)
 * Fail-closed by design (AD-11): a misconfigured provider URL is the common
 * case, and with the provider down binds are blocked either way (A-2) &mdash; a silent boot would
 * only convert a startup-time configuration error into per-bind denials. The refusal surfaces as
 * the standard Spring startup failure (non-zero exit).
 *
 * <p><b>Checks.</b> The discovered {@code issuer} must equal the configured {@code provider-url}
 * exactly (the Keycloak deterministic-issuer property; OIDC Discovery &sect;4.3 makes the issuer
 * the anchor of every downstream JWT claim check) &mdash; mismatch refuses. A provider whose
 * {@code grant_types_supported} omits {@code password} (Direct Access Grants is per-client and off
 * by default since Keycloak 26.2) gets the LOUD DAG warning and defers to runtime: a grant-type
 * error at the token endpoint denies per the AC2 mapping, which is the fail-closed outcome already.
 *
 * <p><b>What survives.</b> The {@link OidcProviderMetadata} record (issuer + token/introspection/
 * jwks endpoints — endpoint URIs come from discovery, no per-endpoint override keys) is the T3
 * adapter's, T4 JWKS cache's and T5 introspection fallback's provider surface. The probe uses a
 * transient {@link HttpClient} closed after the one call; the adapter's steady-state shared client
 * (AC5/AC7 "single shared HttpClient") is built from the same factory outputs in T3. Forward cells
 * carry no oidc node (AD-12 amended 2026-08-18) — the probe stays inactive there.
 */
@Slf4j
@Component
public final class OidcStartupDiscovery {

    /**
     * The loud missing-DAG warning (the Mode B / over-budget banner pattern: a starred block at
     * WARN so it is unmissable in any log aggregation). One {@code {}} slot: the provider URL.
     */
    static final String DAG_WARNING = """
            ************************************************************
            * OIDC PROVIDER DOES NOT ADVERTISE THE password GRANT.
            * Direct Access Grants (ROPC) is per-client and OFF by
            * default since Keycloak 26.2 — enable it on the client,
            * or every password-grant adjudication will be denied by
            * the provider (fail-closed at runtime, AD-11).
            * Deferring to runtime; this is a warning, not a refusal.
            * provider: {}
            ************************************************************""";

    private final @Nullable OidcProviderMetadata metadata;

    /**
     * Eager, fail-closed construction: the probe runs during context refresh (after the
     * {@link IdpSslContextFactory} bean), so a refusal aborts the boot.
     */
    public OidcStartupDiscovery(ProxyCompanionProperties properties, IdpSslContextFactory tlsFactory) {
        Objects.requireNonNull(properties, "properties");
        Objects.requireNonNull(tlsFactory, "tlsFactory");
        IdpSslContextFactory.@Nullable ResolvedOidc resolved = tlsFactory.resolvedOidc();
        if (resolved == null) {
            this.metadata = null;   // forward cells carry no oidc node (AD-12 amended 2026-08-18)
            return;
        }
        this.metadata = probe(resolved, tlsFactory);
    }

    /** Whether this cell ran the discovery probe (every reverse cell: yes; forward cells: no). */
    public boolean active() {
        return metadata != null;
    }

    /** The discovered provider metadata; fails fast on inactive (forward) cells. */
    public OidcProviderMetadata metadata() {
        OidcProviderMetadata resolved = metadata;
        if (resolved == null) {
            throw new IllegalStateException(
                    "no OIDC discovery metadata on this cell — forward cells carry no companion.*.oidc node (AD-12 amended 2026-08-18).");
        }
        return resolved;
    }

    // --- the probe ---------------------------------------------------------------------------

    private static OidcProviderMetadata probe(IdpSslContextFactory.ResolvedOidc resolved,
                                              IdpSslContextFactory tlsFactory) {
        ProxyCompanionProperties.Oidc oidc = resolved.oidc();
        URI discoveryUri = discoveryUri(resolved);
        SSLParameters sslParameters = tlsFactory.sslParameters();
        try (HttpClient http = HttpClient.newBuilder()
                .sslContext(tlsFactory.sslContext())
                .sslParameters(sslParameters)
                .connectTimeout(oidc.timeout())
                .build()) {
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder(discoveryUri).timeout(oidc.timeout()).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw refuse(discoveryUri, "returned HTTP " + response.statusCode(), null);
            }
            return parseDocument(discoveryUri, response.body(), resolved);
        } catch (IOException e) {
            // Unreachable provider / TLS failure / interrupted-at-socket: fail-closed (A-2).
            throw refuse(discoveryUri,
                    "unreachable (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw refuse(discoveryUri, "interrupted", e);
        }
    }

    /**
     * The well-known path under the configured issuer. Since the 2026-08-19 T2 FIXME pass the
     * component arrives {@link URI}-typed and config-layer-canonicalized — {@code CompanionConfigValidator}
     * rejects non-https / hostless URLs at bind time and the {@code Oidc} compact ctor strips the
     * trailing {@code '/'} — so the join here is trivial. (A directly-constructed record bypassing
     * the validator still fails closed below: a hostless URI dies as an unreachable-provider
     * refusal.)
     */
    private static URI discoveryUri(IdpSslContextFactory.ResolvedOidc resolved) {
        return URI.create(resolved.oidc().providerUrl() + "/.well-known/openid-configuration");
    }

    /**
     * Field-completeness first (every endpoint the adapter's three paths need: token, RFC 7662
     * introspection, JWKS — a provider omitting one cannot back the AD-12 contract), then the
     * exact {@code issuer == provider-url} equality, then the DAG warning.
     */
    private static OidcProviderMetadata parseDocument(URI discoveryUri, String body,
                                                      IdpSslContextFactory.ResolvedOidc resolved) {
        Map<String, Object> document;
        try {
            document = JSONObjectUtils.parse(body);
        } catch (ParseException e) {
            throw refuse(discoveryUri, "returned an unparseable document (" + e.getMessage() + ")", e);
        }
        String issuer;
        String tokenEndpoint;
        String introspectionEndpoint;
        String jwksUri;
        try {
            issuer = JSONObjectUtils.getString(document, "issuer");
            tokenEndpoint = JSONObjectUtils.getString(document, "token_endpoint");
            introspectionEndpoint = JSONObjectUtils.getString(document, "introspection_endpoint");
            jwksUri = JSONObjectUtils.getString(document, "jwks_uri");
        } catch (ParseException e) {
            throw refuse(discoveryUri, "carries a malformed field (" + e.getMessage() + ")", e);
        }
        if (issuer == null || tokenEndpoint == null || introspectionEndpoint == null || jwksUri == null) {
            String missing = issuer == null ? "issuer"
                    : tokenEndpoint == null ? "token_endpoint"
                    : introspectionEndpoint == null ? "introspection_endpoint"
                    : "jwks_uri";
            throw refuse(discoveryUri, "omits " + missing + " (incomplete provider metadata)", null);
        }
        String providerUrl = resolved.oidc().providerUrl().toString();
        if (!issuer.equals(providerUrl)) {
            throw new IllegalStateException("OIDC discovery at " + discoveryUri + " returned issuer <"
                    + issuer + "> != configured " + resolved.keyPrefix() + ".oidc.provider-url <"
                    + providerUrl + "> — refusing to start (AD-12).");
        }
        if (!advertisesPasswordGrant(document)) {
            log.warn(DAG_WARNING, providerUrl);
        }
        try {
            return new OidcProviderMetadata(
                    issuer, URI.create(tokenEndpoint), URI.create(introspectionEndpoint), URI.create(jwksUri));
        } catch (IllegalArgumentException e) {
            throw refuse(discoveryUri, "carries a malformed endpoint URI (" + e.getMessage() + ")", e);
        }
    }

    private static boolean advertisesPasswordGrant(Map<String, Object> document) {
        return document.get("grant_types_supported") instanceof List<?> grants
                && grants.stream().anyMatch("password"::equals);
    }

    private static IllegalStateException refuse(URI discoveryUri, String what, @Nullable Throwable cause) {
        String message = "OIDC discovery at " + discoveryUri + " " + what
                + " — refusing to start (AD-12, fail-closed A-2).";
        return cause == null ? new IllegalStateException(message) : new IllegalStateException(message, cause);
    }

    /**
     * The discovered provider surface the T3 adapter (token endpoint), T4 JWKS cache ({@code jwks_uri})
     * and T5 introspection fallback consume; the issuer anchors the local JWT claim checks (AC3).
     */
    public record OidcProviderMetadata(
            String issuer, URI tokenEndpoint, URI introspectionEndpoint, URI jwksUri) {

        public OidcProviderMetadata {
            // F5 fail-fast precedent (2-1 review, a story MUST-keep): a null member would NPE deep
            // inside the adapter. Not jakarta annotations — this record is WIRE-DERIVED (built from
            // the discovery document), so no Bean-Validation pass ever validates it; the compact
            // ctor is the only enforcement point.
            Objects.requireNonNull(issuer, "issuer");
            Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
            Objects.requireNonNull(introspectionEndpoint, "introspectionEndpoint");
            Objects.requireNonNull(jwksUri, "jwksUri");
        }
    }
}
