package smpp.companion.proxy.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.netty.util.AsciiString;

import org.jspecify.annotations.Nullable;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.StructuredTaskScope.Joiner;
import java.util.concurrent.StructuredTaskScope.Subtask;
import java.util.concurrent.atomic.AtomicReference;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.security.OidcStartupDiscovery.OidcProviderMetadata;

/**
 * Story 3.2 T3 (AC2/AC5) — the <b>production</b> ROPC bind adjudicator behind the AC8-immutable
 * {@link BindCredentialVerifier} port (the test-tier ratification slice {@code RopcSlice} lives
 * under {@code src/test}; this class productionizes its shape). Constructed per <b>reverse</b>
 * cell by the security-side wiring: the provider link is {@link IdpSslContextFactory}'s TLS
 * context + AD-34-intersected parameters, the endpoints are {@link OidcStartupDiscovery}'s
 * hard-required startup probe, and the OAuth client credential is the
 * {@code oidc.client-secret-path} file read once here (AD-18).
 *
 * <p><b>AC2 — the refined (normative) verdict table.</b> {@code DenyInvalid} is reserved for the
 * provider's <i>positive invalid-credential signals</i>: a bare 401 (RFC 6749 &sect;5.2 — even
 * with an unparseable body) and a 400 whose parsed OAuth {@code error} is {@code invalid_grant}
 * or {@code invalid_client}. Everything else — 3xx, 403/404/429, other/absent 400 errors, 5xx,
 * timeout, network error, cancellation, admission saturation — is {@code DenyIndeterminate}
 * (rate-limit, configuration and authorization errors are not credential verdicts). This
 * supersedes the test slice's shorthand {@code 4xx} &rarr; {@code DenyInvalid} mapping (recorded in the
 * architecture {@code .memlog.md}, 2026-08-19); the wire impact is none — AD-33 collapses both
 * {@code Deny*} permits identically, the distinction surfaces only in logs/metrics.
 *
 * <p><b>AC5 — concurrency, cancellation, settlement.</b> {@link #verify} never blocks the caller:
 * admission is a {@code tryAcquire} on the {@code oidc.max-in-flight} semaphore (a saturated pool
 * returns {@code DenyIndeterminate} <i>without starting any wire call</i> — {@code sendAsync}
 * fires only after admission is granted), and the adjudication runs on the single bounded
 * virtual-thread {@link ExecutorService} this adapter owns (AD-28(4); never {@code @Async},
 * never a VT-per-bind outside the pool). The {@link RequestContext} is captured
 * <b>synchronously on the caller's thread</b> (the relay binds the {@link ScopedValue} handle
 * only for the dynamic extent of the call — dereferencing it on a pool thread without re-binding
 * throws), then re-bound on the pool thread via the <b>same handle</b> so the structured fan-out
 * inherits it (AD-5, never {@code ThreadLocal}). Within one adjudication the fan-out is a
 * {@link StructuredTaskScope} on the JEP 505 fifth-preview {@code open(Joiner)} API (not the
 * JDK 21/22 {@code ShutdownOnFailure} subclass shape); tearing the exchange down unwinds the
 * scope with it. The adapter <b>guarantees {@code future()} settles</b> (fail-closed) after
 * {@link VerdictRequest#cancelHttp()} — the port itself is silent on settlement, so promising it
 * is additive, and it resolves the relay's cancelled-verdict frame leak at the source.
 *
 * <p><b>Secret hygiene.</b> The ROPC form encodes the password — and the client secret —
 * <b>straight from raw bytes</b>, never {@code AsciiString.toString()} (whose lazy cache would
 * immortalize the secret past any wipe); the assembled form is a {@code byte[]}, never a
 * {@link String}. The <b>password's {@code zeroize()} is CALLER-OWNED</b> (the relay's
 * continuation {@code finally} + teardown wipe, settled 2.2 T7) — this adapter never wipes it:
 * it reads the password asynchronously while its future is pending. The adapter owns and wipes
 * its own material (the loaded client secret on {@link #close}).
 *
 * <p><b>Issued-token adjudication (Story 3.2 T4).</b> A 200 body carrying a JWT is adjudicated
 * <b>locally</b> against {@link JwksCache}'s cached set (signature, {@code typ} per RFC 8725
 * &sect;3.9, {@code iss}/{@code aud}/{@code exp}/{@code nbf} per the clock) &mdash; the AC3
 * defense-in-depth: the token-endpoint 200 is necessary but not sufficient, DENY wins on any local
 * failure. The verify is pure CPU against the <i>cached</i> set &mdash; the bind path NEVER fetches
 * JWKS in the foreground (a {@code kid} miss denies now and schedules a background refresh,
 * {@code AD-12}).
 *
 * <p><b>Opaque-token fallback (Story 3.2 T5, AC4).</b> A 200 body whose token is not a
 * three-segment JWS is adjudicated by <b>RFC 7662 introspection</b>: a second wire arm to the
 * <i>discovery-derived</i> introspection endpoint (no per-endpoint override keys), fired only after
 * the token exchange completed and <b>registered in the same active-call slot</b> (F3 &mdash;
 * {@code cancelHttp()} aborts round 2 exactly as it aborts the token exchange). ONLY HTTP 200 + a
 * JSON body carrying <b>boolean</b> {@code active:true} yields {@code Allow}; every other outcome
 * &mdash; {@code active:false}, a missing or non-boolean {@code active}, a non-JSON body, every
 * non-200 status &mdash; is {@code DenyIndeterminate}: the introspection endpoint carries no
 * positive-invalid signal for the <i>user's</i> credentials (a 401 there is client-auth/config
 * trouble, never the token endpoint's 401 of AC2's {@code DenyInvalid} row). Introspection results
 * are <b>never cached</b> (AD-12 &mdash; every bind re-introspects) and the path never touches the
 * JWKS cache (F6) &mdash; operators should prefer JWT issuance (the {@code Oidc} config javadoc
 * carries that guidance; introspection is online-only with no offline cryptographic backstop).
 */
public final class RopcBindCredentialVerifier implements BindCredentialVerifier, AutoCloseable {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    /**
     * Clock-skew tolerance for the JWT {@code exp}/{@code nbf} claim checks (the ratified slice's
     * value; NTP precondition A-4 keeps real drift far below it).
     */
    private static final Duration CLAIM_SKEW = Duration.ofSeconds(60);

    /**
     * The JOSE-header {@code typ} an issued access token carries (RFC 8725 &sect;3.9 explicit typing).
     * Live-verified against the pinned fixture on 2026-08-19 (Keycloak 26.7.0, ROPC via client A,
     * header decoded straight off the wire): {@code {"alg":"RS256","typ":"JWT","kid":...}} &mdash;
     * <b>"JWT"</b>, not "Bearer" (the {@code "typ":"Bearer"} on that token is the PAYLOAD claim, a
     * different field that RFC 8725 &sect;3.9 does not govern). Absent {@code typ} is tolerated per
     * AC3; a present-but-unexpected value denies.
     */
    private static final JOSEObjectType EXPECTED_TYP = new JOSEObjectType("JWT");

    private final OidcProviderMetadata metadata;
    private final String clientId;
    private final ClientSecret clientSecret;    // ASCII, file-loaded (AD-18); wiped on close (AD-10)
    private final Duration callTimeout;         // oidc.timeout — the per-round-trip budget
    private final HttpClient http;              // the ONE shared provider-facing client (AD-36)
    private final JwksCache jwks;               // cached public keys only — verdicts are never cached (AD-12)
    private final ExecutorService adjudicationPool;   // bounded VT pool (AD-28(4)); the semaphore bounds it
    private final Semaphore admission;

    /**
     * Eager, fail-closed construction (the T2 bean pattern): the client-secret file is read here and a
     * bad one refuses startup; the TLS context/parameters and discovery metadata arrive pre-validated
     * from the T2 beans (they fail the boot on their own).
     *
     * @param tlsFactory the IdP TLS factory (context + AD-34 parameters + the resolved oidc node)
     * @param discovery  the startup discovery probe (must have run — {@code metadata()} fails fast if not)
     */
    public RopcBindCredentialVerifier(IdpSslContextFactory tlsFactory, OidcStartupDiscovery discovery) {
        Objects.requireNonNull(tlsFactory, "tlsFactory");
        Objects.requireNonNull(discovery, "discovery");
        IdpSslContextFactory.@Nullable ResolvedOidc resolved = tlsFactory.resolvedOidc();
        if (resolved == null) {
            throw new IllegalStateException("no IdP link on this cell — the ROPC adapter is wired on "
                    + "reverse cells only (forward cells carry no companion.*.oidc node, "
                    + "AD-12 amended 2026-08-18).");
        }
        ProxyCompanionProperties.Oidc oidc = resolved.oidc();
        this.metadata = discovery.metadata();
        Integer maxInFlight = Objects.requireNonNull(oidc.maxInFlight(), "maxInFlight");
        if (maxInFlight < 1) {
            // Direct construction bypasses the @Min(1) annotation; without this guard Semaphore(0) is
            // valid and EVERY bind silently denies (fail-closed but broken) — the typed capacity guard.
            throw new IllegalArgumentException(resolved.keyPrefix()
                    + ".oidc.max-in-flight must be >= 1 (AD-28(4) admission capacity) — refusing to construct.");
        }
        this.clientId = oidc.clientId();
        this.clientSecret = ClientSecret.load(
                Path.of(oidc.clientSecretPath()), resolved.keyPrefix() + ".oidc.client-secret-path");
        this.callTimeout = Objects.requireNonNull(oidc.timeout(), "timeout");
        this.http = HttpClient.newBuilder()
                .sslContext(tlsFactory.sslContext())
                .sslParameters(tlsFactory.sslParameters())
                .connectTimeout(oidc.timeout())
                .build();
        this.jwks = new JwksCache(this.http, metadata.jwksUri(),
                Objects.requireNonNull(oidc.jwksCacheTtl(), "jwksCacheTtl"), this.callTimeout);
        this.adjudicationPool = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual().name("ropc-adjudication-", 0).factory());
        this.admission = new Semaphore(maxInFlight);
    }

    @Override
    public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
        Objects.requireNonNull(cred, "cred");
        Objects.requireNonNull(ctx, "ctx");   // F12: guard the HANDLE — fail fast, don't silently degrade

        // AC5 capture rule: read the context synchronously HERE, on the caller's thread. The relay binds
        // the handle only for the dynamic extent of this call, so a pool thread cannot dereference it
        // without re-binding; an unbound handle (a caller that skipped the binding) fails CLOSED.
        final RequestContext rc;
        try {
            rc = ctx.get();
        } catch (NoSuchElementException unbound) {
            return settledDeny();
        }

        CompletableFuture<Verdict> pin = new CompletableFuture<>();
        // The in-flight exchange cancelHttp() can abort (AD-32). Null until sendAsync fires — the
        // saturation/expired-budget paths start no wire call, so it stays null there by design. The
        // T5 introspection round TAKES THE SLOT OVER once the token exchange completes (F3), so a
        // cancel landing mid-round-2 aborts that exchange instead.
        AtomicReference<CompletableFuture<HttpResponse<byte[]>>> activeCall = new AtomicReference<>();

        // The adjudication deadline is the verifier's WHOLE budget (the relay arms no timeout of its own,
        // F14): clamp the per-round-trip budget to the time actually left, and deny without a wire call
        // when none is.
        Duration remaining = Duration.between(Instant.now(), rc.deadline());
        if (!remaining.isPositive()) {
            pin.complete(new Verdict.DenyIndeterminate());
            return new RopcVerdictRequest(pin, activeCall);
        }
        Duration budget = callTimeout.compareTo(remaining) < 0 ? callTimeout : remaining;

        // Fail-closed admission (AD-28(4)/F2): a saturated pool denies WITHOUT starting work. sendAsync
        // fires only after tryAcquire succeeds, so a denied bind never transmits the password-bearing
        // form to the provider (the pre-fix shape leaked exactly that).
        if (!admission.tryAcquire()) {
            pin.complete(new Verdict.DenyIndeterminate());
            return new RopcVerdictRequest(pin, activeCall);
        }

        try {
            CompletableFuture<HttpResponse<byte[]>> tokenExchange = http.sendAsync(
                    tokenRequest(cred, budget), HttpResponse.BodyHandlers.ofByteArray());
            // Publish the handle BEFORE verify() returns so cancelHttp() can abort the exchange race-free
            // (the relay only ever cancels the VerdictRequest it got back — after this line).
            activeCall.set(tokenExchange);
            adjudicationPool.execute(() -> settleAdjudication(ctx, rc, tokenExchange, activeCall, pin));
        } catch (RejectedExecutionException | IllegalStateException e) {
            // Use-after-close hardening (deferred-work §2.1 item 2): the pool rejected the task (shut
            // down between acquire and execute) or the shared client is closed. Release the permit,
            // abort whatever fired, settle fail-closed. The PASSWORD is deliberately NOT wiped here —
            // zeroization is caller-owned (relay continuation finally + teardown, settled 2.2 T7).
            admission.release();
            CompletableFuture<HttpResponse<byte[]>> fired = activeCall.get();
            if (fired != null) {
                fired.cancel(true);
            }
            pin.complete(new Verdict.DenyIndeterminate());
        }
        return new RopcVerdictRequest(pin, activeCall);
    }

    /**
     * The pool task: re-bind the context on THIS thread via the same handle (AD-5), run the structured
     * fan-out, settle the pin with its verdict — fail-closed on anything unexpected. The permit is
     * released exactly once here (every early exit still runs the {@code finally}).
     */
    private void settleAdjudication(ScopedValue<RequestContext> ctx, RequestContext rc,
            CompletableFuture<HttpResponse<byte[]>> tokenExchange,
            AtomicReference<CompletableFuture<HttpResponse<byte[]>>> activeCall,
            CompletableFuture<Verdict> pin) {
        try {
            if (pin.isDone()) {
                return;   // cancelHttp() landed before this task started — exchange aborted, verdict settled
            }
            Verdict verdict = ScopedValue.where(ctx, rc).call(() -> adjudicate(tokenExchange, activeCall, rc));
            pin.complete(verdict);
        } catch (Throwable t) {
            pin.complete(new Verdict.DenyIndeterminate());   // fail-closed on any unexpected failure (AD-11)
        } finally {
            admission.release();
        }
    }

    /**
     * The structured fan-out (AD-5). JEP 505 fifth-preview API — {@code open(Joiner)}, NOT the JDK
     * 21/22 {@code ShutdownOnFailure} subclass shape. The T4 JWT defense-in-depth needs no fork: it
     * is pure CPU against the cached JWKS (AC3 forbids a foreground fetch on the bind path). The
     * RFC 7662 introspection round (the opaque-token arm, T5) joins INLINE rather than as a second
     * forked subtask: the fifth-preview scope is <b>single-join</b> — a second {@code join()} after
     * the token arm's throws {@code IllegalStateException} ("Already joined or scope is closed",
     * verified empirically on JDK 25) — so round 2 cannot re-join this scope. The scope is what
     * makes the adjudication shuttable from the teardown path (AD-25): {@code cancelHttp()} cancels
     * the exchange &rarr; the forked {@code join} throws &rarr; {@code join()} fails &rarr;
     * fail-closed below &rarr; {@code close()} unwinds the scope with the subtask; round 2 is
     * cancelled the same way through the F3-registered future (see {@link #introspect}).
     */
    private Verdict adjudicate(CompletableFuture<HttpResponse<byte[]>> tokenExchange,
            AtomicReference<CompletableFuture<HttpResponse<byte[]>>> activeCall, RequestContext rc) {
        try (var scope = StructuredTaskScope.open(Joiner.awaitAllSuccessfulOrThrow())) {
            Subtask<HttpResponse<byte[]>> tokenTask = scope.fork(tokenExchange::join);
            scope.join();   // throws on timeout / network error / cancellation → fail-closed below
            return mapTokenResponse(activeCall, rc, tokenTask.get());
        } catch (Throwable t) {
            return new Verdict.DenyIndeterminate();   // timeout / network error / cancel → AD-11
        }
    }

    /**
     * The AC2 verdict table (normative — see the class javadoc). The 400 arm keys on the PARSED OAuth
     * {@code error} semantics, never the status alone: bad-user credentials arrive as 400
     * {@code invalid_grant} (2-1 fixture finding #6), while rate-limit/config/authz 400s carry other
     * or absent error codes and are not credential verdicts.
     */
    private Verdict mapTokenResponse(AtomicReference<CompletableFuture<HttpResponse<byte[]>>> activeCall,
            RequestContext rc, HttpResponse<byte[]> response) {
        int status = response.statusCode();
        if (status == 200) {
            return adjudicateIssuedToken(activeCall, rc, response.body());
        }
        if (status == 401) {
            // RFC 6749 §5.2: a bare 401 from a token endpoint IS the provider's positive auth-layer
            // rejection — even with an unparseable body (finding #6: bad client → 401 invalid_client).
            return new Verdict.DenyInvalid();
        }
        if (status == 400) {
            String error = oauthError(response.body());
            return "invalid_grant".equals(error) || "invalid_client".equals(error)
                    ? new Verdict.DenyInvalid()
                    : new Verdict.DenyIndeterminate();
        }
        // 3xx (redirects are never followed), 403/404/429, other 4xx, 5xx — not credential verdicts.
        return new Verdict.DenyIndeterminate();
    }

    /** The parsed OAuth {@code error} code of a 400 body; {@code null} when absent or unparseable. */
    private static @Nullable String oauthError(byte[] body) {
        try {
            Map<String, Object> document = JSONObjectUtils.parse(new String(body, StandardCharsets.UTF_8));
            return JSONObjectUtils.getString(document, "error");
        } catch (ParseException e) {
            return null;   // no JSON, no error object → no error semantics → not a credential verdict
        }
    }

    /**
     * The AC2/AC3/AC4 issued-token dispatch. A 200 body must carry an {@code access_token}; a
     * three-segment (JWS) token goes to local JWT defense-in-depth, anything else is an opaque token
     * &rarr; the RFC 7662 introspection arm (AC4). This structural dispatch is what keeps the
     * malformed-JWT row (three segments that do not parse &mdash; JWT territory, denied locally by
     * {@link #verifyJwt}) distinct from the opaque row.
     */
    private Verdict adjudicateIssuedToken(AtomicReference<CompletableFuture<HttpResponse<byte[]>>> activeCall,
            RequestContext rc, byte[] body) {
        String token = accessToken(body);
        if (token == null || token.isBlank()) {
            return new Verdict.DenyIndeterminate();   // no token issued (empty/HTML/no-field body) → unverifiable
        }
        int segments = 1;
        for (int i = 0; i < token.length(); i++) {
            if (token.charAt(i) == '.' && ++segments > 3) {
                break;
            }
        }
        if (segments != 3) {
            return introspect(activeCall, rc, token);   // opaque token → RFC 7662 (AC4)
        }
        return verifyJwt(token);
    }

    /** The {@code access_token} of a 200 token-endpoint body; {@code null} when absent or unparseable. */
    private static @Nullable String accessToken(byte[] body) {
        try {
            Map<String, Object> document = JSONObjectUtils.parse(new String(body, StandardCharsets.UTF_8));
            return JSONObjectUtils.getString(document, "access_token");
        } catch (ParseException e) {
            return null;   // not JSON → no token → unverifiable
        }
    }

    /**
     * Local JWT defense-in-depth against the CACHED JWKS (AC3 &mdash; the ratified slice's
     * {@code verifyWithJwks}, productionized). Every failure &mdash; including an empty cache and a
     * {@code kid} miss &mdash; is <b>unverifiable, not invalid</b>: {@code DenyIndeterminate}, never
     * {@code DenyInvalid} (AD-11; DENY wins on disagreement with the provider's 200). No foreground
     * JWKS fetch ever happens on this path; a {@code kid} miss denies NOW and schedules the
     * background refresh ({@link JwksCache#requestRefresh()}, AD-12).
     */
    @SuppressWarnings("JavaUtilDate")   // reason: Nimbus's claim accessors are java.util.Date-typed —
    // the JOSE API boundary; the logic itself works in Instant and converts only at the call sites.
    private Verdict verifyJwt(String token) {
        JWKSet cached = jwks.current();
        if (cached == null) {
            // Cold cache (the initial refresh has not landed yet): unverifiable, never a wire wait here.
            jwks.requestRefresh();
            return new Verdict.DenyIndeterminate();
        }
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            // RFC 8725 §3.9 explicit typing: absent typ is tolerated (AC3), a present-but-unexpected
            // one denies — cross-JWT confusion (an id_token or refresh token replayed as an access
            // token) must not verify. The expected literal is fixture-verified — see EXPECTED_TYP.
            JOSEObjectType typ = jwt.getHeader().getType();
            if (typ != null && !EXPECTED_TYP.equals(typ)) {
                return new Verdict.DenyIndeterminate();
            }
            String kid = jwt.getHeader().getKeyID();
            if (kid == null) {
                return new Verdict.DenyIndeterminate();
            }
            JWK key = cached.getKeyByKeyId(kid);
            if (key == null) {
                jwks.requestRefresh();   // kid rotation: deny now + background refresh, no foreground retry
                return new Verdict.DenyIndeterminate();
            }
            if (!jwt.verify(new RSASSAVerifier(key.toRSAKey()))) {
                return new Verdict.DenyIndeterminate();   // unverifiable signature → fail-closed
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (!metadata.issuer().equals(claims.getIssuer())) {
                return new Verdict.DenyIndeterminate();
            }
            if (claims.getAudience() == null || !claims.getAudience().contains(clientId)) {
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
            return new Verdict.Allow();   // defense-in-depth passed — the 200 verdict stands
        } catch (Exception e) {
            return new Verdict.DenyIndeterminate();   // malformed JWT / non-RSA key / Nimbus failure → fail-closed
        }
    }

    /**
     * RFC 7662 introspection &mdash; the opaque-token fallback (AC4): the second and last wire arm
     * of an adjudication, fired only after the token exchange completed. The endpoint is the
     * DISCOVERY-derived one (no per-endpoint override keys); the {@code sendAsync} future TAKES OVER
     * the active-call slot (F3: the token exchange is done, so a {@code cancelHttp()} landing now
     * aborts THIS exchange). The round-2 budget is re-clamped to the adjudication deadline's
     * <i>remaining</i> time &mdash; the deadline is the verifier's WHOLE budget, not a per-round
     * allowance. This path never touches the JWKS cache (F6) and its results are never cached
     * (AD-12).
     *
     * <p>The join is INLINE on the pool thread (the ratified slice's shape), not a second forked
     * subtask of the adjudication scope: the JEP 505 fifth-preview scope is <b>single-join</b> &mdash;
     * a second {@code scope.join()} after the token arm's throws {@code IllegalStateException}
     * ("Already joined or scope is closed", verified empirically on JDK 25). Cancellation still
     * reaches round 2 exactly as it reaches the token arm: {@code cancelHttp()} cancels the
     * F3-registered future above, the join throws. The join is uninterruptible, but the clamped
     * request {@code timeout} bounds it &mdash; a lost cancel cannot park the pool thread forever.
     */
    private Verdict introspect(AtomicReference<CompletableFuture<HttpResponse<byte[]>>> activeCall,
            RequestContext rc, String token) {
        Duration remaining = Duration.between(Instant.now(), rc.deadline());
        if (!remaining.isPositive()) {
            return new Verdict.DenyIndeterminate();   // round-2 budget exhausted → no wire call
        }
        Duration budget = callTimeout.compareTo(remaining) < 0 ? callTimeout : remaining;
        CompletableFuture<HttpResponse<byte[]>> intro = http.sendAsync(
                introspectRequest(token, budget), HttpResponse.BodyHandlers.ofByteArray());
        activeCall.set(intro);   // F3: the same slot the token exchange used — cancelHttp() aborts round 2 too
        try {
            return mapIntrospection(intro.join());
        } catch (RuntimeException e) {   // CancellationException / HttpTimeoutException / IO failure
            return new Verdict.DenyIndeterminate();   // fail-closed (AD-11) — never an exception out of the arm
        }
    }

    /**
     * The AC2 introspection rows: ONLY HTTP 200 + a JSON body carrying BOOLEAN {@code active:true}
     * allows. A missing, non-boolean, or false {@code active}, a non-JSON body, and every non-200
     * status deny indeterminately &mdash; none of them is a positive invalid-credential signal for
     * the user's password (contrast the token endpoint's bare-401 row).
     */
    private static Verdict mapIntrospection(HttpResponse<byte[]> response) {
        if (response.statusCode() != 200) {
            return new Verdict.DenyIndeterminate();
        }
        try {
            Map<String, Object> body = JSONObjectUtils.parse(new String(response.body(), StandardCharsets.UTF_8));
            return JSONObjectUtils.getBoolean(body, "active")
                    ? new Verdict.Allow()
                    : new Verdict.DenyIndeterminate();
        } catch (ParseException e) {
            return new Verdict.DenyIndeterminate();   // not JSON / active absent / active not a boolean
        }
    }

    /**
     * Builds the RFC 7662 introspection request. Client auth is RFC 6749 &sect;2.3.1 Basic,
     * assembled from RAW bytes &mdash; the plain secret is never materialized as a {@link String};
     * only its base64 surface (the JDK client's sole header representation) leaves this method, and
     * the concatenated raw buffer is wiped immediately after (AD-10). The token travels in the form
     * body, percent-encoded by the same raw-octet encoder as the ROPC form (AC6: no {@code String}
     * form buffers).
     */
    private HttpRequest introspectRequest(String token, Duration budget) {
        byte[] clientIdBytes = clientId.getBytes(StandardCharsets.US_ASCII);
        byte[] secretBytes = clientSecret.value();
        byte[] basicRaw = new byte[clientIdBytes.length + 1 + secretBytes.length];
        System.arraycopy(clientIdBytes, 0, basicRaw, 0, clientIdBytes.length);
        basicRaw[clientIdBytes.length] = ':';
        System.arraycopy(secretBytes, 0, basicRaw, clientIdBytes.length + 1, secretBytes.length);
        String basic = Base64.getEncoder().encodeToString(basicRaw);
        Arrays.fill(basicRaw, (byte) 0);   // AD-10: the base64 copy exists — wipe the concatenated raw pair

        ByteArrayOutputStream form = new ByteArrayOutputStream(6 + 3 * token.length());
        form.writeBytes("token=".getBytes(StandardCharsets.US_ASCII));
        byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
        urlEncode(form, tokenBytes, 0, tokenBytes.length);
        return HttpRequest.newBuilder(metadata.introspectionEndpoint())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + basic)
                .timeout(budget)
                .POST(HttpRequest.BodyPublishers.ofByteArray(form.toByteArray()))
                .build();
    }

    /**
     * Builds the ROPC token-endpoint request (RFC 6749 &sect;4.3). The password — and the client
     * secret — are form-encoded <b>straight from their raw bytes</b> (F1: never
     * {@code AsciiString.toString()}, whose lazy cache immortalizes the secret past any wipe); the
     * assembled form is a {@code byte[]} handed to the body publisher, never a {@link String}.
     */
    private HttpRequest tokenRequest(BindCredential cred, Duration budget) {
        AsciiString uid = cred.systemId().value();
        AsciiString pw = cred.password().value();
        byte[] secretBytes = clientSecret.value();
        // Exact worst-case bound: every encoded octet is at most 3 bytes (%XX) and the four literal
        // keys + separators sum to 62 ASCII bytes ("grant_type=password&client_id=" 27 + "&username="
        // 10 + "&client_secret=" 15 + "&password=" 10) — the buffer is allocated once, never grows.
        ByteArrayOutputStream form = new ByteArrayOutputStream(
                62 + 3 * (clientId.length() + uid.length() + secretBytes.length + pw.length()));
        form.writeBytes("grant_type=password&client_id=".getBytes(StandardCharsets.US_ASCII));
        byte[] clientIdBytes = clientId.getBytes(StandardCharsets.US_ASCII);
        urlEncode(form, clientIdBytes, 0, clientIdBytes.length);
        form.writeBytes("&username=".getBytes(StandardCharsets.US_ASCII));
        urlEncode(form, uid.array(), uid.arrayOffset(), uid.length());
        form.writeBytes("&client_secret=".getBytes(StandardCharsets.US_ASCII));
        urlEncode(form, clientSecret.value(), 0, clientSecret.value().length);
        form.writeBytes("&password=".getBytes(StandardCharsets.US_ASCII));
        urlEncode(form, pw.array(), pw.arrayOffset(), pw.length());
        return HttpRequest.newBuilder(metadata.tokenEndpoint())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(budget)
                .POST(HttpRequest.BodyPublishers.ofByteArray(form.toByteArray()))
                .build();
    }

    /**
     * {@code application/x-www-form-urlencoded} percent-encoding straight from raw bytes: the RFC 3986
     * unreserved set stays verbatim, every other octet becomes {@code %XX}. Routing the encoding through
     * {@code String}/URLEncoder would materialize a {@link String} of the secret first — exactly what
     * the raw-byte rule forbids.
     *
     * <p>Deliberately not Apache Commons Codec's {@code URLCodec}: commons-codec is on no proxy
     * classpath today (a NEW runtime dependency for a twelve-line encoder), its {@code www-form-url}
     * safe set differs from RFC 3986 unreserved ({@code *} allowed, {@code ~} escaped), and the
     * security/ adapter stack stays JDK+Nimbus by design (AD-36's dependency-minimalism — the same
     * rule that kept {@code oauth2-oidc-sdk} out, 2026-08-19 owner note).
     */
    private static void urlEncode(ByteArrayOutputStream out, byte[] raw, int offset, int length) {
        for (int i = 0; i < length; i++) {
            int c = raw[offset + i] & 0xff;
            if (isUnreserved(c)) {
                out.write(c);
            } else {
                out.write('%');
                out.write(HEX[(c >> 4) & 0xf]);
                out.write(HEX[c & 0xf]);
            }
        }
    }

    private static boolean isUnreserved(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '-' || c == '.' || c == '_' || c == '~';
    }

    private static VerdictRequest settledDeny() {
        CompletableFuture<Verdict> pin = new CompletableFuture<>();
        pin.complete(new Verdict.DenyIndeterminate());
        return new RopcVerdictRequest(pin, new AtomicReference<>());
    }

    /**
     * The {@link VerdictRequest}: {@code cancelHttp()} aborts the in-flight exchange
     * ({@code cancel(true)} — the only sanctioned JDK-client abort path, mayInterruptIfRunning is what
     * closes the connection) AND settles the future fail-closed — the adapter's settlement guarantee:
     * after {@code cancelHttp()} the future is ALWAYS completed (with {@code DenyIndeterminate}),
     * never left dangling. Idempotent: no-ops once settled, and on the saturation/expired paths where
     * no wire call ever started.
     */
    private record RopcVerdictRequest(CompletableFuture<Verdict> pin,
                                      AtomicReference<CompletableFuture<HttpResponse<byte[]>>> activeCall)
            implements VerdictRequest {

        @Override
        public CompletableFuture<Verdict> future() {
            return pin;
        }

        @Override
        public void cancelHttp() {
            CompletableFuture<HttpResponse<byte[]>> call = activeCall.get();
            if (call != null) {
                call.cancel(true);
            }
            pin.complete(new Verdict.DenyIndeterminate());
        }
    }

    /**
     * The JWKS cache handle, package-private for the component-level tests (the slice's
     * {@code verifyWithJwks} package-private precedent): cold-cache and refresh-cycle behavior is a
     * {@link JwksCache} contract, asserted directly rather than through full binds.
     */
    JwksCache jwksCache() {
        return jwks;
    }

    /**
     * Minimal shutdown seam (the T7 lifecycle stop body — deny in-flight with {@code shutdownNow()} +
     * await + fail-closed log, AD-22 ordering once the JWKS refresh exists — wraps this): denying
     * in-flight is structural — {@code shutdownNow()} interrupts the pool tasks, each settles its pin
     * fail-closed in its catch, and every post-close verify settles via the use-after-close arm above.
     * The JWKS refresh stops FIRST (AD-22: refresh before cache close) so no refresh races the
     * closing shared client.
     */
    @Override
    public void close() {
        jwks.close();   // AD-22: stop the refresh scheduler before anything it could still use closes
        adjudicationPool.shutdownNow();
        http.close();
        clientSecret.zeroize();   // AD-10: the adapter's own secret material
    }
}
