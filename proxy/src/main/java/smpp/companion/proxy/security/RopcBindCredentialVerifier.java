package smpp.companion.proxy.security;

import com.nimbusds.jose.util.JSONObjectUtils;

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
 * <p><b>Pending arms (Story 3.2 T4/T5).</b> A 200 body is not yet adjudicated to {@code Allow}:
 * local JWT defense-in-depth against the cached JWKS (T4) and the RFC 7662 opaque-token
 * introspection fallback (T5) plug into the fan-out; until they land, every issued token is
 * unverifiable &rarr; fail-closed {@code DenyIndeterminate} (AD-11).
 */
public final class RopcBindCredentialVerifier implements BindCredentialVerifier, AutoCloseable {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private final OidcProviderMetadata metadata;
    private final String clientId;
    private final ClientSecret clientSecret;    // ASCII, file-loaded (AD-18); wiped on close (AD-10)
    private final Duration callTimeout;         // oidc.timeout — the per-round-trip budget
    private final HttpClient http;              // the ONE shared provider-facing client (AD-36)
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
        // saturation/expired-budget paths start no wire call, so it stays null there by design.
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
            adjudicationPool.execute(() -> settleAdjudication(ctx, rc, tokenExchange, pin));
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
            CompletableFuture<HttpResponse<byte[]>> tokenExchange, CompletableFuture<Verdict> pin) {
        try {
            if (pin.isDone()) {
                return;   // cancelHttp() landed before this task started — exchange aborted, verdict settled
            }
            Verdict verdict = ScopedValue.where(ctx, rc).call(() -> adjudicate(tokenExchange));
            pin.complete(verdict);
        } catch (Throwable t) {
            pin.complete(new Verdict.DenyIndeterminate());   // fail-closed on any unexpected failure (AD-11)
        } finally {
            admission.release();
        }
    }

    /**
     * The structured fan-out (AD-5). JEP 505 fifth-preview API — {@code open(Joiner)}, NOT the JDK
     * 21/22 {@code ShutdownOnFailure} subclass shape. T4 forks the JWKS defense-in-depth arm and T5
     * the introspection arm into this same scope; T3's fan is the token exchange alone. The scope is
     * what makes the adjudication shuttable from the teardown path (AD-25): {@code cancelHttp()}
     * cancels the exchange &rarr; the forked {@code join} throws &rarr; {@code join()} fails &rarr;
     * fail-closed below &rarr; {@code close()} unwinds the scope with the subtask.
     */
    private Verdict adjudicate(CompletableFuture<HttpResponse<byte[]>> tokenExchange) {
        try (var scope = StructuredTaskScope.open(Joiner.awaitAllSuccessfulOrThrow())) {
            Subtask<HttpResponse<byte[]>> tokenTask = scope.fork(tokenExchange::join);
            scope.join();   // throws on timeout / network error / cancellation → fail-closed below
            return mapTokenResponse(tokenTask.get());
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
            // An issued token becomes Allow only through local JWT defense-in-depth (T4) or RFC 7662
            // introspection (T5); until those arms land, every 200 body is UNVERIFIABLE → fail-closed
            // (AD-11 — "unverifiable" is NOT "invalid"). The body bytes are not even read here.
            return new Verdict.DenyIndeterminate();
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
     * Minimal shutdown seam (the T7 lifecycle stop body — deny in-flight with {@code shutdownNow()} +
     * await + fail-closed log, AD-22 ordering once the JWKS refresh exists — wraps this): denying
     * in-flight is structural — {@code shutdownNow()} interrupts the pool tasks, each settles its pin
     * fail-closed in its catch, and every post-close verify settles via the use-after-close arm above.
     */
    @Override
    public void close() {
        adjudicationPool.shutdownNow();
        http.close();
        clientSecret.zeroize();   // AD-10: the adapter's own secret material
    }
}
