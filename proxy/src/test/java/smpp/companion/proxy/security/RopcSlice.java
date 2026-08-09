package smpp.companion.proxy.security;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.netty.util.AsciiString;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.StructuredTaskScope.Joiner;
import java.util.concurrent.StructuredTaskScope.Subtask;

/**
 * Story 2.1 Task 2 — the <b>test-tier</b> ROPC validation slice that ratifies the AD-12 {@code proxy/security/}
 * port contract's shape against a real Keycloak &ge;26.7.0 across all four AD-12 paths. It is NOT the production
 * adapter (Epic 3): it lives under {@code proxy/src/test}, uses {@link java.net.http.HttpClient} + Nimbus, and
 * proves the {@link BindCredentialVerifier} port can <b>express</b> every path (Allow JWT / Allow introspection /
 * Allow mTLS / DenyInvalid / DenyIndeterminate) before {@code relay/} commits against it (AC2/AC8).
 *
 * <p><b>Concurrency model (AC4 / AD-5):</b> each adjudication fans the ROPC token call and the local JWKS
 * defense-in-depth fetch out on a {@link StructuredTaskScope} (JEP 505 preview — {@code open(Joiner)} +
 * {@code fork} + {@code join}) with the {@link RequestContext} bound via {@link ScopedValue} (JEP 506 final),
 * <b>never {@link ThreadLocal}</b>. The fan-out runs on one bounded hand-managed virtual-thread
 * {@link ExecutorService} owned by this slice (AD-28(4)); admission is fail-closed on saturation (AC6).
 *
 * <p><b>Fail-closed + secret hygiene (AC5 / AD-11):</b> the {@link Password} backing array is zeroized on
 * adjudication completion (success or failure); verdicts are never cached (re-validate every bind); JWKS is
 * cached only. Non-401-non-verifiable responses, 5xx, timeouts, network errors, and JWKS {@code kid} misses
 * collapse to {@link Verdict.DenyIndeterminate}; 4xx collapses to {@link Verdict.DenyInvalid}; DENY always wins.
 *
 * <p><b>Cancellation (AC3 / AD-32):</b> {@link VerdictRequest#cancelHttp()} aborts the underlying
 * {@code HttpClient} exchange (not only the future), tearing the {@link StructuredTaskScope} down so the IdP is
 * spared the abandoned ROPC call. {@code cancelHttp()} on the open exchange (T3's wire-abort test) is exercised
 * by a later task; this adapter wires the binding now.
 *
 * <p>API shape note (AC4 guardrail, AD-5/AD-35): {@link StructuredTaskScope} is JEP 505 <i>preview</i>; the exact
 * {@code Joiner} signatures below were verified against the live JDK 25 ({@code StructuredTaskScope.open(Joiner)},
 * {@code Joiner.awaitAllSuccessfulOrThrow()}, {@code Subtask.get()}). It may change again — re-verify at impl time.
 */
public final class RopcSlice implements BindCredentialVerifier, AutoCloseable {

    /** Per-path configuration: which Keycloak client / OAuth mode / verdict strategy this slice adjudicates. */
    public record SliceConfig(
            URI tokenEndpoint,
            URI introspectionEndpoint,
            URI jwksUri,
            String issuer,
            String clientId,
            /* Path 1/2/4 client secret; null for path 3 (mTLS authenticates the client, RFC 8705). */
            String clientSecret,
            /* Path 3: the transport cert authenticates the client; no client_secret is sent. */
            boolean useMtlsClientAuth,
            /* Path 2: introspect the issued token (RFC 7662) instead of local JWKS defense-in-depth verify. */
            boolean introspect) {
    }

    /** Clock-skew tolerance for JWT {@code exp}/{@code nbf} claim checks (AD-11). */
    private static final Duration CLAIM_SKEW = Duration.ofSeconds(60);

    private final HttpClient http;
    private final SliceConfig cfg;
    private final ExecutorService adjudicationPool;   // bounded hand-managed VT pool (AD-28(4))
    private final Semaphore admission;                // bounds in-flight adjudications → fail-closed on saturation (AC6)
    private final java.util.concurrent.atomic.AtomicReference<JWKSet> jwksCache =
            new java.util.concurrent.atomic.AtomicReference<>();   // JWKS cached only (AD-12); verdicts never

    /**
     * @param http         the mTLS-capable {@link HttpClient} (trusts the fixture CA, presents the client cert).
     * @param cfg          the per-path slice configuration.
     * @param maxInflight  the bounded-VT-pool admission limit; saturation returns {@link Verdict.DenyIndeterminate}
     *                     immediately (fail-closed, AC6 / AD-28(4)).
     */
    public RopcSlice(HttpClient http, SliceConfig cfg, int maxInflight) {
        this.http = Objects.requireNonNull(http, "http");
        this.cfg = Objects.requireNonNull(cfg, "cfg");
        if (maxInflight < 1) {
            throw new IllegalArgumentException("maxInflight must be >= 1");
        }
        this.adjudicationPool = Executors.newVirtualThreadPerTaskExecutor();
        this.admission = new Semaphore(maxInflight);
    }

    @Override
    public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
        Objects.requireNonNull(cred, "cred");
        RequestContext rc = ctx != null && ctx.isBound() ? ctx.get() : null;
        Instant now = Instant.now();
        Instant deadline = rc != null ? rc.deadline() : now.plusSeconds(30);
        Duration callTimeout = clamp(Duration.between(now, deadline), Duration.ofSeconds(1), Duration.ofSeconds(30));

        CompletableFuture<HttpResponse<String>> tokenExchange =
                http.sendAsync(tokenRequest(cred, callTimeout), HttpResponse.BodyHandlers.ofString());
        CompletableFuture<Verdict> pin = new CompletableFuture<>();

        // Fail-closed admission (AC6): a saturated pool denies indeterminate without starting work.
        if (!admission.tryAcquire()) {
            tokenExchange.cancel(true);
            pin.complete(new Verdict.DenyIndeterminate());
            cred.password().zeroize();
            return new RopcVerdictRequest(pin, tokenExchange);
        }

        // The adjudication runs on the bounded VT pool. The RequestContext is re-bound on the pool thread via the
        // SAME ScopedValue handle the caller used, so the STS fan-out inside adjudicate() inherits it (AD-5).
        adjudicationPool.execute(() -> {
            try {
                Verdict v = (rc != null)
                        ? ScopedValue.where(ctx, rc).call(() -> adjudicate(tokenExchange))
                        : adjudicate(tokenExchange);
                pin.complete(v);
            } catch (Throwable t) {
                pin.complete(new Verdict.DenyIndeterminate());   // fail-closed on any unexpected failure (AD-11)
            } finally {
                admission.release();
                cred.password().zeroize();
            }
        });

        return new RopcVerdictRequest(pin, tokenExchange);
    }

    /**
     * The STS fan-out (AC4 / AD-5): fork the ROPC token call and the JWKS defense-in-depth fetch concurrently,
     * {@code join} them, then collapse to one {@link Verdict}. A network error / timeout / scope cancellation in
     * either subtask fails the {@code awaitAllSuccessfulOrThrow} join and collapses to {@link Verdict.DenyIndeterminate}.
     */
    private Verdict adjudicate(CompletableFuture<HttpResponse<String>> tokenExchange) {
        char[] tokenChars = null;
        try (var scope = StructuredTaskScope.open(Joiner.awaitAllSuccessfulOrThrow())) {
            Subtask<HttpResponse<String>> tokenTask = scope.fork(() -> tokenExchange.join());
            Subtask<JWKSet> jwksTask = scope.fork(this::fetchJwks);
            scope.join();   // both subtasks succeeded, else throws → catch → DenyIndeterminate

            HttpResponse<String> tokenResp = tokenTask.get();
            TokenOutcome outcome = mapTokenResponse(tokenResp);
            tokenChars = outcome.tokenChars();

            if (outcome.tokenChars() == null) {
                return mapNon200(outcome.status());   // no token issued: 4xx → DenyInvalid, else DenyIndeterminate
            }
            String accessToken = new String(tokenChars);
            try {
                return cfg.introspect()
                        ? adjudicateByIntrospection(accessToken)
                        : verifyWithJwks(jwksTask.get(), accessToken);
            } finally {
                Arrays.fill(tokenChars, '\0');   // AC5: zeroize the access-token working copy
                tokenChars = null;
            }
        } catch (Throwable t) {
            return new Verdict.DenyIndeterminate();   // network error / timeout / cancellation → fail-closed (AD-11)
        } finally {
            if (tokenChars != null) {
                Arrays.fill(tokenChars, '\0');
            }
        }
    }

    /** Local JWKS defense-in-depth verify (AC2 path 1; AD-11). Package-private for the kid-miss unit test. */
    Verdict verifyWithJwks(JWKSet jwks, String accessToken) {
        try {
            SignedJWT jwt = SignedJWT.parse(accessToken);
            String kid = jwt.getHeader().getKeyID();
            if (kid == null) {
                return new Verdict.DenyIndeterminate();
            }
            JWK key = jwks.getKeyByKeyId(kid);
            if (key == null) {
                asyncRefreshJwks();   // kid absent → background refresh, no foreground retry (AD-12) → DENY now
                return new Verdict.DenyIndeterminate();
            }
            JWSVerifier verifier = new RSASSAVerifier(key.toRSAKey());
            if (!jwt.verify(verifier)) {
                return new Verdict.DenyIndeterminate();   // unverifiable signature → fail-closed
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (!Objects.equals(claims.getIssuer(), cfg.issuer())) {
                return new Verdict.DenyIndeterminate();
            }
            if (claims.getAudience() == null || !claims.getAudience().contains(cfg.clientId())) {
                return new Verdict.DenyIndeterminate();
            }
            Instant now = Instant.now();
            if (claims.getExpirationTime() == null
                    || claims.getExpirationTime().before(Date.from(now.minus(CLAIM_SKEW)))) {
                return new Verdict.DenyIndeterminate();
            }
            if (claims.getNotBeforeTime() != null
                    && claims.getNotBeforeTime().after(Date.from(now.plus(CLAIM_SKEW)))) {
                return new Verdict.DenyIndeterminate();
            }
            return new Verdict.Allow();
        } catch (Exception e) {
            return new Verdict.DenyIndeterminate();   // malformed JWT / parse failure → fail-closed (AD-11)
        }
    }

    /** RFC 7662 introspection (AC2 path 2): {@code active:true} → Allow; any other outcome → fail-closed DENY. */
    private Verdict adjudicateByIntrospection(String accessToken) {
        try {
            HttpResponse<String> r = http.send(introspectRequest(accessToken), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                return new Verdict.DenyIndeterminate();
            }
            Map<String, Object> body = JSONObjectUtils.parse(r.body());
            boolean active = JSONObjectUtils.getBoolean(body, "active");
            return active ? new Verdict.Allow() : new Verdict.DenyIndeterminate();
        } catch (Exception e) {
            return new Verdict.DenyIndeterminate();   // malformed introspection response → fail-closed (AD-11)
        }
    }

    /** Parses the token-endpoint response: a 200 with an {@code access_token} yields the token; else no token. */
    private TokenOutcome mapTokenResponse(HttpResponse<String> resp) {
        if (resp.statusCode() != 200) {
            return new TokenOutcome(resp.statusCode(), null);
        }
        try {
            Map<String, Object> body = JSONObjectUtils.parse(resp.body());
            String at = JSONObjectUtils.getString(body, "access_token");
            if (at == null || at.isBlank()) {
                return new TokenOutcome(resp.statusCode(), null);   // 200 with no JWT → unverifiable
            }
            return new TokenOutcome(resp.statusCode(), at.toCharArray());
        } catch (Exception e) {
            return new TokenOutcome(resp.statusCode(), null);   // malformed token response → unverifiable
        }
    }

    /** AD-11 path-4 mapping (refined by the real fixture, finding #6): 4xx → DenyInvalid; else DenyIndeterminate. */
    private static Verdict mapNon200(int status) {
        return (status >= 400 && status < 500) ? new Verdict.DenyInvalid() : new Verdict.DenyIndeterminate();
    }

    private HttpRequest tokenRequest(BindCredential cred, Duration timeout) {
        AsciiString uid = cred.systemId().value();
        AsciiString pw = cred.password().value();
        StringBuilder body = new StringBuilder()
                .append("grant_type=password")
                .append("&client_id=").append(URLEncoder.encode(cfg.clientId(), StandardCharsets.UTF_8))
                .append("&username=").append(URLEncoder.encode(uid.toString(), StandardCharsets.UTF_8));
        if (cfg.useMtlsClientAuth()) {
            // Path 3: the transport cert authenticates the client (RFC 8705 tls_client_auth) — NO client_secret.
        } else if (cfg.clientSecret() != null) {
            body.append("&client_secret=").append(URLEncoder.encode(cfg.clientSecret(), StandardCharsets.UTF_8));
        }
        // Form-encode the password like the non-secret fields (StringBuilder + URLEncoder + ofString below)
        // instead of from the raw AsciiString byte[]. ACCEPTED HAZARD: pw.toString() makes Netty cache an
        // immortal String of the secret (CODEC-024 P2 / AI-5) — fine for this throwaway test slice; the Epic 3
        // production adapter MUST encode the password from the raw byte[] (never toString()).
        body.append("&password=").append(URLEncoder.encode(pw.toString(), StandardCharsets.UTF_8));
        return HttpRequest.newBuilder(cfg.tokenEndpoint())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
    }

    private HttpRequest introspectRequest(String accessToken) {
        String basic = Base64.getEncoder()
                .encodeToString((cfg.clientId() + ":" + cfg.clientSecret()).getBytes(StandardCharsets.US_ASCII));
        String body = "token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
        return HttpRequest.newBuilder(cfg.introspectionEndpoint())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + basic)
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
    }

    private JWKSet fetchJwks() {
        JWKSet cached = jwksCache.get();
        if (cached != null) {
            return cached;
        }
        try {
            HttpResponse<String> r = http.send(
                    HttpRequest.newBuilder(cfg.jwksUri()).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                throw new IllegalStateException("JWKS non-200: " + r.statusCode());
            }
            JWKSet parsed = JWKSet.parse(r.body());
            jwksCache.compareAndSet(null, parsed);
            return parsed;
        } catch (Exception e) {
            throw new IllegalStateException("JWKS fetch failed", e);
        }
    }

    private void asyncRefreshJwks() {
        jwksCache.set(null);   // invalidate; the next bind re-fetches. Background refresh, no foreground retry.
        adjudicationPool.execute(() -> {
            try {
                fetchJwks();
            } catch (Exception ignored) {
                // Background best-effort; a failed refresh surfaces as DenyIndeterminate on the next bind.
            }
        });
    }

    private static Duration clamp(Duration d, Duration min, Duration max) {
        if (d.compareTo(min) < 0) {
            return min;
        }
        if (d.compareTo(max) > 0) {
            return max;
        }
        return d;
    }

    /** The token-endpoint outcome: status + the access-token working copy (or {@code null} if none issued). */
    private record TokenOutcome(int status, char[] tokenChars) {
    }

    /** The {@link VerdictRequest}: exposes the verdict future and binds {@code cancelHttp()} to the exchange abort. */
    private record RopcVerdictRequest(CompletableFuture<Verdict> pin,
                                      CompletableFuture<HttpResponse<String>> tokenExchange) implements VerdictRequest {
        @Override
        public CompletableFuture<Verdict> future() {
            return pin;
        }

        @Override
        public void cancelHttp() {
            // AD-32: abort the underlying HTTP ROPC call (not only the future). Idempotent: no-op once settled.
            tokenExchange.cancel(true);
            pin.complete(new Verdict.DenyIndeterminate());
        }
    }

    @Override
    public void close() {
        adjudicationPool.shutdownNow();
    }
}
