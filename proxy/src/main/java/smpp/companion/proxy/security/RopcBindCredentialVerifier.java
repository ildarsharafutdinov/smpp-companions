package smpp.companion.proxy.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.netty.util.AsciiString;

import lombok.extern.slf4j.Slf4j;

import org.jspecify.annotations.Nullable;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Flow;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.TimeUnit;
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
 * its own material on every completion path (AC6): each adjudication registers its form buffers
 * and the parsed response bodies, and zeroizes them in its pool task's {@code finally} (the
 * loaded client secret is wiped once at {@link #close}). The forms
 * publish ZERO-COPY — {@link FormPublisher} hands the JDK the registered array itself
 * ({@code BodyPublishers.ofByteArray} would copy the whole credential-bearing form into heap
 * chunks no wipe can reach, JDK-source verified) — so the registered array is the one and only copy.
 *
 * <p><b>Issued-token adjudication (Story 3.2 T4).</b> A 200 body carrying a JWT is adjudicated
 * <b>locally</b> against {@link JwksCache}'s cached set (signature, {@code typ} per RFC 8725
 * &sect;3.9, {@code iss}/{@code aud}/{@code exp}/{@code nbf} per the clock) &mdash; the AC3
 * defense-in-depth: the token-endpoint 200 is necessary but not sufficient, DENY wins on any local
 * failure. The verify is pure CPU against the <i>cached</i> set &mdash; the bind path NEVER fetches
 * JWKS in the foreground (a {@code kid} miss denies now and schedules a background refresh,
 * {@code AD-12}).
 *
 * <p><b>JWT-only policy (Story 3.4 T1 / D6, 2026-08-27 — supersedes the 3.2-era AC4 opaque-token
 * fallback).</b> There is no second wire arm: a 200 body whose token is not a three-segment JWS
 * is not adjudicable — the verdict is {@code DenyIndeterminate} plus a WARN naming the JWT-only
 * policy and the operator remediation (configure the client/realm to issue JWT access tokens).
 * Owner rationale (2026-08-27): the pinned single-operator Keycloak (&ge;26.7.0) issues JWTs at
 * its token endpoint, the proxy is the token's only consumer, and a second wire arm with its own
 * client-auth path is interop surface this deployment does not need (amendment record: AD-12).
 * Fail-closed (AD-11): never an allow, never a silent skip.
 */
@Slf4j
public final class RopcBindCredentialVerifier implements BindCredentialVerifier, AutoCloseable {

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
     * from the T2 beans (they fail the boot on their own). The one shared provider-facing client is
     * {@link IdpSslContextFactory#newClient()} — this factory's TLS posture, single-sourced.
     *
     * @param tlsFactory the IdP TLS factory (context + AD-34 parameters + the resolved oidc node)
     * @param discovery  the startup discovery probe (must have run — {@code metadata()} fails fast if not)
     */
    public RopcBindCredentialVerifier(IdpSslContextFactory tlsFactory, OidcStartupDiscovery discovery) {
        this(tlsFactory, discovery, tlsFactory.newClient());
    }

    /**
     * Direct client injection: the shared provider-facing {@link HttpClient} arrives built. The
     * 2-arg ctor passes {@link IdpSslContextFactory#newClient()} — the single TLS-posture recipe;
     * the T6 cancellation/zeroization suites pass a recording wrapper around the same build (to
     * observe the real {@code sendAsync} futures and the adapter's exact request buffers), so every
     * construction path is injection, with the recipe owned by the factory.
     */
    RopcBindCredentialVerifier(IdpSslContextFactory tlsFactory, OidcStartupDiscovery discovery,
            HttpClient http) {
        Objects.requireNonNull(tlsFactory, "tlsFactory");
        Objects.requireNonNull(discovery, "discovery");
        this.http = Objects.requireNonNull(http, "http");
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

        Adjudication adj = new Adjudication(rc);

        // The adjudication deadline is the verifier's WHOLE budget (the relay arms no timeout of its own,
        // F14): clamp the per-round-trip budget to the time actually left, and deny without a wire call
        // when none is.
        Duration remaining = Duration.between(Instant.now(), rc.deadline());
        if (!remaining.isPositive()) {
            adj.pin.complete(new Verdict.DenyIndeterminate());
            return new RopcVerdictRequest(adj.pin, adj.activeCall);
        }
        Duration budget = callTimeout.compareTo(remaining) < 0 ? callTimeout : remaining;

        // Fail-closed admission (AD-28(4)/F2): a saturated pool denies WITHOUT starting work. sendAsync
        // fires only after tryAcquire succeeds, so a denied bind never transmits the password-bearing
        // form to the provider (the pre-fix shape leaked exactly that).
        if (!admission.tryAcquire()) {
            adj.pin.complete(new Verdict.DenyIndeterminate());
            return new RopcVerdictRequest(adj.pin, adj.activeCall);
        }

        try {
            CompletableFuture<HttpResponse<byte[]>> tokenExchange = http.sendAsync(
                    tokenRequest(cred, budget, adj), HttpResponse.BodyHandlers.ofByteArray());
            // Publish the handle BEFORE verify() returns so cancelHttp() can abort the exchange race-free
            // (the relay only ever cancels the VerdictRequest it got back — after this line).
            adj.activeCall.set(tokenExchange);
            adjudicationPool.execute(() -> settleAdjudication(ctx, adj, tokenExchange));
        } catch (RejectedExecutionException | IllegalStateException e) {
            // Use-after-close hardening (deferred-work §2.1 item 2): the pool rejected the task (shut
            // down between acquire and execute) or the shared client is closed. Release the permit,
            // abort whatever fired, zeroize the form (this catch is its only completion path — the
            // pool task never started), settle fail-closed. The PASSWORD is deliberately NOT wiped
            // here — zeroization is caller-owned (relay continuation finally + teardown, 2.2 T7).
            admission.release();
            CompletableFuture<HttpResponse<byte[]>> fired = adj.activeCall.get();
            if (fired != null) {
                fired.cancel(true);
            }
            adj.zeroizeSensitive();
            adj.pin.complete(new Verdict.DenyIndeterminate());
        }
        return new RopcVerdictRequest(adj.pin, adj.activeCall);
    }

    /**
     * The pool task: re-bind the context on THIS thread via the same handle (AD-5), run the structured
     * fan-out, settle the pin with its verdict — fail-closed on anything unexpected. The {@code finally}
     * is the adjudication's completion path (AD-10(3)): the permit frees FIRST (a waiting bind never
     * queues behind a wipe), then every registered secret buffer is zeroized — whatever the verdict was.
     */
    private void settleAdjudication(ScopedValue<RequestContext> ctx, Adjudication adj,
            CompletableFuture<HttpResponse<byte[]>> tokenExchange) {
        try {
            if (adj.pin.isDone()) {
                return;   // cancelHttp() landed before this task started — exchange aborted, verdict settled
            }
            Verdict verdict = ScopedValue.where(ctx, adj.rc).call(() -> adjudicate(adj, tokenExchange));
            adj.pin.complete(verdict);
        } catch (Throwable t) {
            adj.pin.complete(new Verdict.DenyIndeterminate());   // fail-closed on any unexpected failure (AD-11)
        } finally {
            admission.release();
            adj.zeroizeSensitive();
        }
    }

    /**
     * The structured fan-out (AD-5). JEP 505 fifth-preview API — {@code open(Joiner)}, NOT the JDK
     * 21/22 {@code ShutdownOnFailure} subclass shape. One forked arm: the token exchange. The T4
     * JWT defense-in-depth needs no fork: it is pure CPU against the cached JWKS (AC3 forbids a
     * foreground fetch on the bind path). The scope is what makes the adjudication shuttable from
     * the teardown path (AD-25): {@code cancelHttp()} cancels the exchange &rarr; the forked
     * {@code join} throws &rarr; fail-closed below &rarr; the scope closes with the subtask.
     * (History: the 3.2-era opaque-token round joined INLINE on the pool thread — the
     * fifth-preview scope is <b>single-join</b>, a second {@code join()} throws
     * {@code IllegalStateException} — that arm was removed by Story 3.4 T1, 2026-08-27.)
     */
    private Verdict adjudicate(Adjudication adj, CompletableFuture<HttpResponse<byte[]>> tokenExchange) {
        try (var scope = StructuredTaskScope.open(Joiner.awaitAllSuccessfulOrThrow())) {
            Subtask<HttpResponse<byte[]>> tokenTask = scope.fork(tokenExchange::join);
            scope.join();   // throws on timeout / network error / cancellation → fail-closed below
            HttpResponse<byte[]> response = tokenTask.get();
            adj.registerSensitive(response.body());   // AC6: the body carries the issued access token
            return mapTokenResponse(response);
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
    private Verdict mapTokenResponse(HttpResponse<byte[]> response) {
        int status = response.statusCode();
        if (status == 200) {
            return adjudicateIssuedToken(response.body());
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
     * The AC2/AC3 issued-token dispatch. A 200 body must carry an {@code access_token}; a
     * three-segment (JWS) token goes to local JWT defense-in-depth, anything else is a non-JWT
     * (opaque) token &rarr; the D6 fail-closed deny (Story 3.4 T1, 2026-08-27 — there is no
     * second wire arm to ask). This structural dispatch is what keeps the malformed-JWT row
     * (three segments that do not parse &mdash; JWT territory, denied locally by {@link #verifyJwt})
     * distinct from the opaque row.
     */
    private Verdict adjudicateIssuedToken(byte[] body) {
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
            // D6 (Story 3.4 T1, 2026-08-27): JWT-only adjudication — an opaque token is not
            // adjudicable, and there is no second wire arm to ask. Fail-closed deny, never an
            // allow; the WARN carries the policy and the operator remediation (token shape is
            // observable only here, at bind time — a startup probe would need a real credential).
            log.warn("the token endpoint issued a non-JWT (opaque) access token — the JWT-only "
                    + "adjudication policy (Story 3.4 T1/D6, 2026-08-27) denies fail-closed; "
                    + "operator remediation: configure the client/realm to issue JWT access tokens.");
            return new Verdict.DenyIndeterminate();
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
     * Builds the ROPC token-endpoint request (RFC 6749 &sect;4.3). The password — and the client
     * secret — are form-encoded <b>straight from their raw bytes</b> (F1: never
     * {@code AsciiString.toString()}, whose lazy cache immortalizes the secret past any wipe); the
     * assembled form is a {@code byte[]} handed to the body publisher, never a {@link String}.
     */
    private HttpRequest tokenRequest(BindCredential cred, Duration budget, Adjudication adj) {
        AsciiString uid = cred.systemId().value();
        AsciiString pw = cred.password().value();
        byte[] secretBytes = clientSecret.value();
        // Exact worst-case bound: every encoded octet is at most 3 bytes (%XX) and the four literal
        // keys + separators sum to 62 ASCII bytes ("grant_type=password&client_id=" 27 + "&username="
        // 10 + "&client_secret=" 15 + "&password=" 10) — the buffer is allocated once, never grows.
        FormBuffer form = new FormBuffer(
                62 + 3 * (clientId.length() + uid.length() + secretBytes.length + pw.length()));
        form.literal("grant_type=password&client_id=")
                .urlEncoded(clientId.getBytes(StandardCharsets.US_ASCII), 0, clientId.length())
                .literal("&username=")
                .urlEncoded(uid.array(), uid.arrayOffset(), uid.length())
                .literal("&client_secret=")
                .urlEncoded(secretBytes, 0, secretBytes.length)
                .literal("&password=")
                .urlEncoded(pw.array(), pw.arrayOffset(), pw.length());
        adj.registerSensitive(form.backingArray());   // AC6: the form carries the password + client secret
        return HttpRequest.newBuilder(metadata.tokenEndpoint())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(budget)
                .POST(new FormPublisher(form.backingArray(), form.length()))
                .build();
    }

    /**
     * One in-flight adjudication's mutable state (AC5/AC6): the verdict pin, the
     * cancelHttp()-abortable wire-call slot (F3 — the token exchange's future; published before
     * {@link #verify} returns so the cancel is race-free), the captured {@link RequestContext},
     * and the registry of the adapter's OWN secret buffers. Created on the caller's thread inside
     * {@link #verify}; the pool task takes it over from there. The registry is zeroized on every
     * completion path (AD-10(3)) — the pool task's {@code finally} and the use-after-close catch
     * in {@link #verify}.
     *
     * <p>Deliberately NOT registered: the bind password's backing array (zeroization is
     * CALLER-OWNED, F1/2.2 T7 — the adapter reads it asynchronously while its future is pending)
     * and the file-loaded client secret (wiped once at {@link #close}); the registry holds only
     * per-adjudication transient copies.
     */
    private static final class Adjudication {
        final CompletableFuture<Verdict> pin = new CompletableFuture<>();
        final AtomicReference<CompletableFuture<HttpResponse<byte[]>>> activeCall = new AtomicReference<>();
        final RequestContext rc;
        private final List<byte[]> sensitiveBuffers = new ArrayList<>(4);

        Adjudication(RequestContext rc) {
            this.rc = rc;
        }

        /** Registers one of the adapter's own secret arrays (a form, token bytes, a parsed body). */
        void registerSensitive(byte[] buffer) {
            sensitiveBuffers.add(buffer);
        }

        /** Zeroizes every registered array — the AD-10(3) wipe, on completion paths only. */
        void zeroizeSensitive() {
            for (byte[] buffer : sensitiveBuffers) {
                Arrays.fill(buffer, (byte) 0);
            }
        }
    }

    /**
     * The form builder (AC6): one bound-allocated {@code byte[]} with a write cursor — no
     * {@link java.io.ByteArrayOutputStream}, so building a form never materializes a SECOND
     * secret-bearing array (the stream's internal buffer plus its {@code toByteArray} copy). The
     * buffer is allocated at the exact worst-case bound, never grows, and the published request
     * body IS this array (see {@link FormPublisher}) — the single copy an adjudication registers
     * and wipes.
     */
    private static final class FormBuffer {

        private static final char[] HEX = "0123456789ABCDEF".toCharArray();

        private final byte[] buf;
        private int len;

        FormBuffer(int bound) {
            buf = new byte[bound];
        }

        /** Appends verbatim ASCII — the literal keys and separators. */
        FormBuffer literal(String ascii) {
            byte[] bytes = ascii.getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(bytes, 0, buf, len, bytes.length);
            len += bytes.length;
            return this;
        }

        /**
         * Appends {@code application/x-www-form-urlencoded} percent-encoding straight from raw
         * bytes: the RFC 3986 unreserved set stays verbatim, every other octet becomes
         * {@code %XX}. Routing the encoding through {@code String}/URLEncoder would materialize a
         * {@link String} of the secret first — exactly what the raw-byte rule forbids.
         */
        FormBuffer urlEncoded(byte[] raw, int offset, int length) {
            for (int i = 0; i < length; i++) {
                int c = raw[offset + i] & 0xff;
                if (isUnreserved(c)) {
                    buf[len] = (byte) c;
                    len += 1;
                } else {
                    buf[len] = '%';
                    buf[len + 1] = (byte) HEX[(c >> 4) & 0xf];
                    buf[len + 2] = (byte) HEX[c & 0xf];
                    len += 3;
                }
            }
            return this;
        }

        private static boolean isUnreserved(int c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~';
        }

        byte[] backingArray() {
            return buf;
        }

        int length() {
            return len;
        }
    }

    /**
     * The request-body publisher for the forms (AC6): hands the JDK client the adapter's EXACT
     * buffer — {@code ByteBuffer.wrap}, zero copies. {@link HttpRequest.BodyPublishers#ofByteArray}
     * copies the whole credential-bearing form into fresh heap chunks at subscribe time
     * (JDK-source verified, 25.0.3), leaving secret copies the adapter cannot reach with any
     * wipe; publishing the wrapped buffer keeps the form to the ONE array the adjudication
     * registers and zeroizes. Single-item delivery — the forms are always fully buffered, so one
     * {@code onNext} followed by {@code onComplete} is the whole contract.
     */
    static final class FormPublisher implements HttpRequest.BodyPublisher {

        private final byte[] buffer;
        private final int length;

        FormPublisher(byte[] buffer, int length) {
            this.buffer = buffer;
            this.length = length;
        }

        /** The adapter's exact form array — what the adjudication registers and wipes (AC6). */
        byte[] buffer() {
            return buffer;
        }

        @Override
        public long contentLength() {
            return length;
        }

        @Override
        public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {
            Objects.requireNonNull(subscriber);
            subscriber.onSubscribe(new Flow.Subscription() {
                private boolean delivered;

                @Override
                public void request(long n) {
                    if (n <= 0) {
                        subscriber.onError(new IllegalArgumentException("non-positive request"));
                        return;
                    }
                    if (!delivered) {
                        delivered = true;
                        subscriber.onNext(ByteBuffer.wrap(buffer, 0, length));
                        subscriber.onComplete();
                    }
                }

                @Override
                public void cancel() {
                    delivered = true;
                }
            });
        }
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
     * The T7 AD-22 stop body (invoked by {@link AdjudicationLifecycle}; also the inferred destroy
     * method — idempotent, the failed-boot backstop). Order: <b>deny in-flight FIRST</b> —
     * {@code shutdownNow()} interrupts every pool task (each settles its pin fail-closed in its
     * catch) and {@code awaitTermination} bounds the drain at the per-request budget + 1s, logging
     * fail-closed and proceeding on timeout (the hard close below aborts whatever exchanges
     * remain, and every aborted join settles {@code DenyIndeterminate}) — <b>then</b> the JWKS
     * refresh stops (AD-22: refresh before the cache's own client closes, so no refresh races it)
     * and the shared client + the client secret are released.
     */
    @Override
    public void close() {
        adjudicationPool.shutdownNow();   // AD-22 step 2: deny in-flight
        // The drain bound: in-flight tasks are self-bounded by the per-request timeout clamp, so the
        // budget + 1s always suffices — the timeout arm below is defensive, and the hard close that
        // follows forces the unwind regardless (fail-closed, deferred-work §2.1 item 5).
        Duration drainBudget = callTimeout.plusSeconds(1);
        try {
            if (!adjudicationPool.awaitTermination(drainBudget.toMillis(), TimeUnit.MILLISECONDS)) {
                log.warn("the adjudication pool did not drain within {} — proceeding with the hard close "
                        + "(every in-flight adjudication settles DenyIndeterminate; AD-22 fail-closed).",
                        drainBudget);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("the adjudication drain was interrupted — proceeding with the hard close "
                    + "(every in-flight adjudication settles DenyIndeterminate; AD-22 fail-closed).");
        }
        jwks.close();   // AD-22: stop the refresh scheduler before the client it fetches through closes
        http.close();
        clientSecret.zeroize();   // AD-10: the adapter's own secret material
    }
}
