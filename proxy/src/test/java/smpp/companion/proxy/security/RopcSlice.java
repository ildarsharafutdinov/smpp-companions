package smpp.companion.proxy.security;

import com.nimbusds.jose.util.JSONObjectUtils;
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
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.StructuredTaskScope.Joiner;
import java.util.concurrent.StructuredTaskScope.Subtask;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Story 2.1 Task 2 — the <b>test-tier</b> ROPC validation slice that ratifies the AD-12 {@code proxy/security/}
 * port contract's shape against a real Keycloak &ge;26.7.0. It is NOT the production adapter
 * ({@code RopcBindCredentialVerifier}): it lives under {@code proxy/src/test}, uses
 * {@link java.net.http.HttpClient} + Nimbus, and proves the {@link BindCredentialVerifier} port can
 * <b>express</b> the contract's verdicts before {@code relay/} commits against it (AC2/AC8).
 *
 * <p><b>Amended contract (Story 3.4 T8, 2026-08-29 — supersedes the 2.1 four-path shape and the 2026-08-27
 * T1/T2 "deliberately UNCHANGED" disposition):</b> the slice's historical-ratification exemption is ENDED —
 * local JWT signature verification (JWKS fetch/cache/refresh), RFC 7662 opaque-token introspection, and the
 * RFC 8705 {@code tokenRequest} mTLS client-auth branch are removed from the test tier too, and the slice
 * becomes the LIVE ratification of the amended contract: a ROPC grant with mandatory {@code client_secret}
 * whose verdict derives from the token-endpoint response + the STRUCTURAL three-segment gate alone
 * (JWT &rarr; {@code Allow}; opaque &rarr; {@code DenyIndeterminate}). The slice's transport TLS stays (the
 * mTLS {@link SSLContext} presents the client cert on every call — the trust anchor); only the OAuth-level
 * cert-auth arm is gone.
 *
 * <p><b>Concurrency model (AC4 / AD-5):</b> each adjudication runs the ROPC token call under a
 * {@link StructuredTaskScope} (JEP 505 preview — {@code open(Joiner)} + {@code fork} + {@code join}) with the
 * {@link RequestContext} bound via {@link ScopedValue} (JEP 506 final), <b>never {@link ThreadLocal}</b>.
 * One forked arm — the token exchange — since the local-verify arm died with the verification (the
 * production adapter's shape, Story 3.4 T2). The adjudication runs on one bounded hand-managed
 * virtual-thread {@link ExecutorService} owned by this slice (AD-28(4)); admission is fail-closed on
 * saturation (AC6).
 *
 * <p><b>Fail-closed + secret hygiene (AC5 / AD-11):</b> the {@link Password} backing array is zeroized on
 * adjudication completion (success or failure); verdicts are never cached (re-validate every bind); the
 * access-token working copy is zeroized after the gate. Non-verifiable responses, 5xx, timeouts, network
 * errors, and non-three-segment (opaque) tokens collapse to {@link Verdict.DenyIndeterminate}; 4xx collapses
 * to {@link Verdict.DenyInvalid} (the slice's shorthand non-200 mapping, recorded in the architecture
 * {@code .memlog.md}, 2026-08-19); DENY always wins.
 *
 * <p><b>Cancellation (AC3 / AD-32):</b> {@link VerdictRequest#cancelHttp()} aborts the underlying
 * {@code HttpClient} exchange (not only the future), tearing the {@link StructuredTaskScope} down so the IdP is
 * spared the abandoned ROPC call. {@code cancelHttp()} binds the token exchange ALONE — the slice has no
 * second wire arm to abort (Story 3.4 T8).
 *
 * <p>API shape note (AC4 guardrail, AD-5/AD-35): {@link StructuredTaskScope} is JEP 505 <i>preview</i>; the exact
 * {@code Joiner} signatures below were verified against the live JDK 25 ({@code StructuredTaskScope.open(Joiner)},
 * {@code Joiner.awaitAllSuccessfulOrThrow()}, {@code Subtask.get()}). It may change again — re-verify at impl time.
 */
public final class RopcSlice implements BindCredentialVerifier, AutoCloseable {

    /**
     * Per-slice configuration: the token endpoint + the confidential client's id/secret (the amended contract's
     * whole OAuth surface — {@code client_secret} is MANDATORY; the mTLS no-secret and introspection modes died
     * with Story 3.4 T8, 2026-08-29).
     */
    public record SliceConfig(
            URI tokenEndpoint,
            String clientId,
            String clientSecret) {
        public SliceConfig {
            // Compact constructor — fail-fast (AD-17): a null field would otherwise NPE deep inside
            // tokenRequest()/verify() — escaping verify() as a raw Throwable (fail-open) with the password never zeroized.
            Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
            Objects.requireNonNull(clientId, "clientId");
            Objects.requireNonNull(clientSecret, "clientSecret");
        }
    }

    private final HttpClient http;
    private final SliceConfig cfg;
    private final ExecutorService adjudicationPool;   // bounded hand-managed VT pool (AD-28(4))
    private final Semaphore admission;                // bounds in-flight adjudications → fail-closed on saturation (AC6)

    /**
     * @param http         the TLS-capable {@link HttpClient} (trusts the fixture CA, presents the client cert —
     *                     transport identity; OAuth-level auth is {@code client_secret} only, Story 3.4 T8).
     * @param cfg          the slice configuration (token endpoint + confidential client).
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
        Objects.requireNonNull(ctx, "ctx");   // F12: @param ctx non-null contract — fail fast, don't silently degrade
        RequestContext rc = ctx.isBound() ? ctx.get() : null;
        Instant now = Instant.now();
        Instant deadline = rc != null ? rc.deadline() : now.plusSeconds(30);
        Duration callTimeout = clamp(Duration.between(now, deadline), Duration.ofSeconds(1), Duration.ofSeconds(30));

        CompletableFuture<Verdict> pin = new CompletableFuture<>();
        // The in-flight HTTP call cancelHttp() can abort (AD-32): the token exchange — the slice's ONLY wire call
        // since the introspection arm died (Story 3.4 T8). Null on the saturation/denied path — no wire call is
        // started there.
        AtomicReference<CompletableFuture<HttpResponse<String>>> activeCall = new AtomicReference<>();

        // Fail-closed admission (AC6): a saturated pool denies indeterminate WITHOUT starting work — the wire call is
        // fired only AFTER admission is granted (below), so a denied bind never transmits the ROPC request (F2: the
        // pre-fix shape fired sendAsync before tryAcquire, leaking the password-bearing request to the IdP).
        if (!admission.tryAcquire()) {
            pin.complete(new Verdict.DenyIndeterminate());
            cred.password().zeroize();
            return new RopcVerdictRequest(pin, activeCall);
        }

        // Admission granted — fire the ROPC token call now (after the admission decision) on the caller thread and
        // publish its handle to activeCall before returning, so cancelHttp() can abort it race-free. The adjudication
        // itself runs on the bounded VT pool; the RequestContext is re-bound on the pool thread via the SAME
        // ScopedValue handle the caller used, so the STS fan-out inside adjudicate() inherits it (AD-5).
        CompletableFuture<HttpResponse<String>> tokenExchange =
                http.sendAsync(tokenRequest(cred, callTimeout), HttpResponse.BodyHandlers.ofString());
        activeCall.set(tokenExchange);

        adjudicationPool.execute(() -> {
            try {
                if (pin.isDone()) {
                    return;   // cancelHttp() landed before the pool task started — exchange already aborted; bail
                }
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

        return new RopcVerdictRequest(pin, activeCall);
    }

    /**
     * The STS fan-out (AC4 / AD-5): fork the token exchange, {@code join} it, then collapse to one
     * {@link Verdict}. One forked arm — the ONLY arm since the local JWT verify and the introspection round were
     * removed everywhere (Story 3.4 T8, 2026-08-29; the production adapter took the same shape at T2). A network
     * error / timeout / scope cancellation fails the {@code awaitAllSuccessfulOrThrow} join and collapses to
     * {@link Verdict.DenyIndeterminate}.
     */
    private Verdict adjudicate(CompletableFuture<HttpResponse<String>> tokenExchange) {
        char[] tokenChars = null;
        try (var scope = StructuredTaskScope.open(Joiner.awaitAllSuccessfulOrThrow())) {
            Subtask<HttpResponse<String>> tokenTask = scope.fork(tokenExchange::join);
            scope.join();   // the forked subtask succeeded, else throws → catch → DenyIndeterminate

            HttpResponse<String> tokenResp = tokenTask.get();
            TokenOutcome outcome = mapTokenResponse(tokenResp);
            tokenChars = outcome.tokenChars();

            if (outcome.tokenChars() == null) {
                return mapNon200(outcome.status());   // no token issued: 4xx → DenyInvalid, else DenyIndeterminate
            }
            String accessToken = new String(tokenChars);
            try {
                return adjudicateIssuedToken(accessToken);
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

    /**
     * The issued-token dispatch, aligned to the amended contract (Story 3.4 T8, 2026-08-29; mirroring the production
     * adapter's D6/D7 arms). The token is checked ONLY structurally: exactly three {@code '.'}-separated segments
     * (a JWS) is the provider's "issues JWT access tokens" requirement satisfied — {@code Allow}, derived from the
     * endpoint verdict alone (D7: no signature verification, no claim checks, no provider-key fetch; content past
     * the segment count is never parsed). Anything else is a non-JWT (opaque) token &rarr; the D6 fail-closed deny
     * — there is no second wire arm to ask. The segment count is deliberately library-free.
     */
    private static Verdict adjudicateIssuedToken(String accessToken) {
        int segments = 1;
        for (int i = 0; i < accessToken.length(); i++) {
            if (accessToken.charAt(i) == '.' && ++segments > 3) {
                break;
            }
        }
        if (segments != 3) {
            // D6: JWT-only adjudication — an opaque token is not adjudicable, and there is no introspection arm to
            // ask (it never existed in the amended contract's slice). Fail-closed deny, never an allow.
            return new Verdict.DenyIndeterminate();
        }
        // D7: the TLS client-authenticated provider link is the sole trust anchor — nothing re-proves the
        // provider's signature locally (the proxy is this token's only consumer).
        return new Verdict.Allow();
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
        // The amended contract's whole client-auth surface: the confidential client's secret, ALWAYS sent (the
        // RFC 8705 no-secret branch died with Story 3.4 T8, 2026-08-29 — transport TLS stays, OAuth-level cert
        // auth does not).
        StringBuilder body = new StringBuilder()
                .append("grant_type=password")
                .append("&client_id=").append(URLEncoder.encode(cfg.clientId(), StandardCharsets.UTF_8))
                .append("&username=").append(URLEncoder.encode(uid.toString(), StandardCharsets.UTF_8))
                .append("&client_secret=").append(URLEncoder.encode(cfg.clientSecret(), StandardCharsets.UTF_8));
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
                                      AtomicReference<CompletableFuture<HttpResponse<String>>> activeCall)
            implements VerdictRequest {
        @Override
        public CompletableFuture<Verdict> future() {
            return pin;
        }

        @Override
        public void cancelHttp() {
            // AD-32: abort the in-flight HTTP call — the token exchange, the slice's only wire call (the
            // introspection second arm died with Story 3.4 T8, 2026-08-29). Idempotent: no-op once settled, and a
            // no-op on the saturation/denied path where no wire call was ever started (activeCall is null — F2/AC6).
            CompletableFuture<HttpResponse<String>> c = activeCall.get();
            if (c != null) {
                c.cancel(true);
            }
            pin.complete(new Verdict.DenyIndeterminate());
        }
    }

    @Override
    public void close() {
        adjudicationPool.shutdownNow();
    }
}
