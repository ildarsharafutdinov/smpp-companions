package smpp.companion.proxy.security;

import com.nimbusds.jose.util.JSONObjectUtils;

import io.netty.util.AsciiString;

import lombok.extern.slf4j.Slf4j;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
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
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Flow;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.StructuredTaskScope.Joiner;
import java.util.concurrent.StructuredTaskScope.Subtask;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import smpp.companion.proxy.config.ProxyCompanionProperties;

/**
 * Story 3.2 T3 (AC2/AC5) — the <b>production</b> ROPC bind adjudicator behind the AC8-immutable
 * {@link BindCredentialVerifier} port (the test-tier ratification slice {@code RopcSlice} lives
 * under {@code src/test}; this class productionizes its shape). Constructed per <b>reverse</b>
 * cell by the security-side wiring: the provider link is {@link IdpSslContextFactory}'s TLS
 * context + AD-34-intersected parameters, the token endpoint is DERIVED from the configured
 * {@code provider-url} ({@link #deriveTokenEndpoint(URI)} — no provider wire call at startup
 * since Story 3.4 T9), and the OAuth client credential is the
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
 * <p><b>TLS-as-sole-trust-anchor (Story 3.4 T2 / D7, 2026-08-27 — supersedes the 3.2-T4 local JWT
 * defense-in-depth).</b> Local signature verification and everything that fed it — the verify arm,
 * the cached provider key set, its background refresh thread, its TTL knob, and the discovery
 * key-set URI requirement — is REMOVED: the proxy is the issued token's ONLY consumer (it never
 * forwards, caches, nor shows it to anyone), and re-proving the provider's honesty locally guards
 * against a threat
 * that already owns the AD-12-mandated HTTPS, client-authenticated provider link the keys came
 * over. {@code Allow} therefore derives from the token endpoint's own response alone; the only
 * surviving token check is the STRUCTURAL three-segment (JWS) gate — the provider
 * &quot;issues JWTs&quot; requirement, cheap and library-free. Unverified claim checks
 * ({@code typ}/{@code iss}/{@code aud}/{@code exp}/{@code nbf}/{@code kid}) went with the
 * verification — theater once the endpoint verdict already decided (amendment record: AD-12).
 *
 * <p><b>JWT-only policy (Story 3.4 T1 / D6, 2026-08-27 — supersedes the 3.2-era AC4 opaque-token
 * fallback).</b> There is no second wire arm: a 200 body whose token is not a three-segment JWS
 * is not adjudicable — the verdict is {@code DenyIndeterminate} plus a WARN naming the JWT-only
 * policy and the operator remediation (configure the client/realm to issue JWT access tokens).
 * Owner rationale (2026-08-27): the pinned single-operator Keycloak (&ge;26.7.0) issues JWTs at
 * its token endpoint, the proxy is the token's only consumer, and a second wire arm with its own
 * client-auth path is interop surface this deployment does not need (amendment record: AD-12).
 * Fail-closed (AD-11): never an allow, never a silent skip.
 *
 * <p><b>No startup provider call (Story 3.4 T9, 2026-08-29 — supersedes the 3.2-T2 hard-required
 * discovery probe; owner-directed &quot;simplify app&quot;).</b> The probe, its discovery-document
 * GET, the {@code issuer == provider-url} equality, and the Direct-Access-Grants warning are
 * REMOVED whole: the token endpoint is DERIVED from the configured {@code provider-url} (the
 * pinned-Keycloak realm path, {@link #deriveTokenEndpoint(URI)}), and provider misconfiguration
 * &mdash; a typo'd or dead {@code provider-url}, a DAG-off client &mdash; denies fail-closed at
 * FIRST BIND via the unchanged AC2 mapping, now with a starred operator WARN
 * ({@link #OPERATOR_WARNING}) that fires ONCE PER CONDITION (the Story 4.1 T5 flood bound,
 * 2026-09-03) naming the derived endpoint, the {@code provider-url}, and the
 * remediation — every later occurrence of the same condition logs
 * {@link #OPERATOR_WARNING_REPEAT} instead, so a dead provider under sustained binds cannot
 * bury the log under banner repeats. The Direct-Access-Grants prerequisite is an operator contract carried by the
 * application.yml policy block and the {@code Oidc.providerUrl} javadoc, not a runtime probe.
 */
@Slf4j
public final class RopcBindCredentialVerifier implements BindCredentialVerifier, AutoCloseable {

    /**
     * The pinned-Keycloak realm-relative token path (Story 3.4 T9, 2026-08-29). Keycloak serves
     * every realm's OIDC endpoints under {@code <realm-base>/protocol/openid-connect/*}, so the
     * token endpoint is DERIVED from the configured {@code provider-url} (which MUST be the realm
     * base) — byte-identical to the realm layout the fixture containers serve
     * ({@code KeycloakFixture.TOKEN_ENDPOINT} in the test tier) and to the endpoint the test-tier
     * {@code RopcSlice} injects directly (aligned to it by Story 3.4 T8).
     */
    static final String TOKEN_ENDPOINT_PATH = "protocol/openid-connect/token";

    /**
     * The path-join contract (Story 3.4 T9): {@code token endpoint = provider-url + '/' +
     * TOKEN_ENDPOINT_PATH}, byte-identical to the pinned-Keycloak realm layout. The join
     * APPENDS after the base's last path segment (the realm name) — plain {@link URI#resolve}
     * with a relative reference would REPLACE that segment per RFC 3986 &sect;5.3, so the
     * separator is added explicitly over the {@code Oidc} compact ctor's slash-stripped base
     * (never doubled: a base that kept a trailing {@code '/'} — only constructible by bypassing
     * that ctor — derives the same endpoint). The join is PURE DERIVATION, no wire call: a
     * {@code provider-url} that is not the realm base yields an endpoint the provider answers
     * with a non-mapped status, which denies fail-closed at first bind with the operator WARN —
     * the retired startup probe's loud successor.
     */
    static URI deriveTokenEndpoint(URI providerUrl) {
        String base = providerUrl.toString();
        return URI.create(base.endsWith("/")
                ? base + TOKEN_ENDPOINT_PATH
                : base + "/" + TOKEN_ENDPOINT_PATH);
    }

    /**
     * The loud operator WARN (Story 3.4 T9, 2026-08-29 — the retired startup-refusal/DAG-warning
     * posture's successor; the Mode B / over-budget banner pattern: a starred block so it is
     * unmissable in any log aggregation). Logged on the token-call connection-error and
     * non-mapped-non-200 arms — the arms a typo'd {@code provider-url}, a dead provider, or a
     * Direct-Access-Grants-off client land on (transient provider statuses — 3xx/403/404/429/5xx —
     * share the arm; the verdict stays {@code DenyIndeterminate} either way). Log-only: the verdict table (AC2) is
     * unchanged. Three {@code {}} slots: what happened, the derived token endpoint, the
     * configured provider-url.
     *
     * <p><b>The flood bound (Story 4.1 T5, checkpoint 16, 2026-09-03).</b> The banner fires ONCE
     * PER CONDITION (the 2026-09-01 review's per-bind-flooding row, deferred to this story): under
     * a dead or typo'd provider every denied bind used to re-emit these ~14 lines — up to
     * {@code max-in-flight} concurrent — burying the log and the aggregation the banner is meant to
     * be unmissable in. Later occurrences of the same condition log
     * {@link #OPERATOR_WARNING_REPEAT} instead.
     */
    static final String OPERATOR_WARNING = """
            ************************************************************
            * OIDC TOKEN CALL FAILED — THE BIND IS DENIED FAIL-CLOSED.
            * A provider misconfiguration surfaces HERE, at first bind,
            * not at startup (the startup OIDC discovery probe was
            * removed, Story 3.4 T9, 2026-08-29; the verdict mapping is
            * unchanged — this is a warning, not a refusal).
            * {}
            * token endpoint: {}
            * provider-url:  {}
            * Operator remediation: provider-url must be the Keycloak
            * REALM base (the token endpoint is derived as
            * <provider-url>/protocol/openid-connect/token), the
            * provider must be reachable over the trusted TLS link, and
            * the client must have Direct Access Grants enabled
            * (per-client and OFF by default since Keycloak 26.2) —
            * otherwise every bind denies fail-closed.
            ************************************************************""";

    /**
     * The repeat one-liner (Story 4.1 T5, checkpoint 16): every occurrence of a condition whose
     * {@link #OPERATOR_WARNING} banner already fired logs this ONE line — per-bind visibility
     * without the per-bind flood. Two {@code {}} slots: the per-occurrence detail (the same line
     * the banner's first occurrence carried — a repeat may name a message variant the banner's
     * occurrence did not) and the derived token endpoint (multi-cell operators grep by provider).
     */
    static final String OPERATOR_WARNING_REPEAT = "OIDC token call failed again — {} — token endpoint: {};"
            + " the starred operator banner for this condition fired once above; this bind denies"
            + " fail-closed (AD-11)";

    /**
     * The condition key of the opaque-token arm (Story 4.1 T5): a single literal — the issued token
     * is not a three-segment JWS. Nothing finer is honest to key on (the token VALUE must never
     * reach a key — secret hygiene), so the arm is one condition per adapter.
     */
    static final String OPAQUE_TOKEN_CONDITION = "opaque-token";

    /**
     * The full opaque-token operator warning (D6 arm), aligned to the banner PATTERN by Story 4.1
     * T5 (checkpoint 16): fires once per {@link #OPAQUE_TOKEN_CONDITION}, and now carries the
     * derived token endpoint and {@code provider-url} (the 2026-09-01 review's multi-cell context
     * gap — an operator of several cells could not tell WHICH provider issued the opaque token).
     * Deliberately NOT the starred {@link #OPERATOR_WARNING}: its headline would lie here — the
     * token call SUCCEEDED (HTTP 200); the JWT-only policy is what denies. Two {@code {}} slots:
     * the derived token endpoint, the configured provider-url.
     */
    static final String OPAQUE_TOKEN_WARNING = "the token endpoint issued a non-JWT (opaque) access token — "
            + "the JWT-only adjudication policy (Story 3.4 T1/D6, 2026-08-27) denies fail-closed; "
            + "operator remediation: configure the client/realm to issue JWT access tokens "
            + "(token endpoint: {}; provider-url: {})";

    /**
     * The opaque-token repeat one-liner (Story 4.1 T5): later occurrences of the same condition log
     * this ONE line — the same bound {@link #OPERATOR_WARNING_REPEAT} applies to the failure arms.
     * One {@code {}} slot: the derived token endpoint.
     */
    static final String OPAQUE_TOKEN_WARNING_REPEAT = "the token endpoint issued a non-JWT (opaque) access "
            + "token again — denied fail-closed under the JWT-only policy (the full policy warning "
            + "fired once above; token endpoint: {})";

    private final URI providerUrl;           // the configured realm base — named in the WARN (T9)
    private final URI tokenEndpoint;         // DERIVED from provider-url at wiring (T9)
    private final String clientId;
    private final ClientSecret clientSecret;    // ASCII, file-loaded (AD-18); wiped on close (AD-10)
    private final Duration callTimeout;         // oidc.timeout — the per-round-trip budget
    private final HttpClient http;              // the ONE shared provider-facing client (AD-36)
    private final ExecutorService adjudicationPool;   // bounded VT pool (AD-28(4)); the semaphore bounds it
    private final Semaphore admission;
    /**
     * The VT-gauge seam (Story 4.1 T3, checkpoint 9): the in-flight adjudication count behind
     * {@link #activeAdjudications()}. Incremented at pool SUBMIT (on the caller's thread, before
     * {@code execute}) and decremented in the pool task's {@code finally}; a pool rejection between
     * the two compensates inline, so the count can never leak. Observation only — it gates no
     * behavior (the wrap adds no restructuring of the pool; the sanctioned VT-gauge seam edit).
     */
    private final AtomicLong activeAdjudications;
    /** Set at {@link #close()} entry (code review 2026-09-01, owner-sanctioned): the adapter's OWN
     *  shutdown aborts are not provider misconfiguration — the transport-arm operator WARN stays off
     *  routine restarts. Verdicts are unaffected (still {@code DenyIndeterminate}). */
    private volatile boolean closed;
    /**
     * The T5 flood bound's condition memory (Story 4.1 checkpoint 16, 2026-09-03): the conditions
     * whose FULL operator warning has already fired. Keys draw from closed sets BY CONSTRUCTION —
     * the transport arm keys on the failure's {@code IOException} class name, the status arm on
     * {@code status:<code>} ONLY (HTTP status codes; the provider-echoed OAuth error string rides
     * the detail line, never the key — step-04 review, finding #6), the opaque arm on one literal —
     * so the set cannot grow per-bind, per-attacker, per-error-echo, or per-token-value. Fire
     * sites run on the adjudication pool's virtual threads; {@link Set#add} on the concurrent set
     * is the atomic once-test (returns true exactly for the condition's first occurrence).
     */
    private final Set<String> operatorWarnedConditions = ConcurrentHashMap.newKeySet();

    /**
     * Eager, fail-closed construction (the T2 bean pattern): the client-secret file is read here and a
     * bad one refuses startup; the TLS context/parameters arrive pre-validated from the T2 bean
     * (it fails the boot on its own). The one shared provider-facing client is
     * {@link IdpSslContextFactory#newClient()} — this factory's TLS posture, single-sourced.
     * NO provider wire call happens here (Story 3.4 T9, 2026-08-29): the token endpoint is
     * derived from the configured {@code provider-url} in this ctor, so a wrong or dead
     * provider-url constructs fine and denies fail-closed at FIRST bind (AC2 unchanged) with
     * {@link #OPERATOR_WARNING}.
     *
     * @param tlsFactory the IdP TLS factory (context + AD-34 parameters + the resolved oidc node)
     */
    public RopcBindCredentialVerifier(IdpSslContextFactory tlsFactory) {
        this(tlsFactory, tlsFactory.newClient());
    }

    /**
     * Direct client injection: the shared provider-facing {@link HttpClient} arrives built. The
     * public ctor passes {@link IdpSslContextFactory#newClient()} — the single TLS-posture recipe;
     * the T6 cancellation/zeroization suites pass a recording wrapper around the same build (to
     * observe the real {@code sendAsync} futures and the adapter's exact request buffers), so every
     * construction path is injection, with the recipe owned by the factory.
     */
    RopcBindCredentialVerifier(IdpSslContextFactory tlsFactory, HttpClient http) {
        Objects.requireNonNull(tlsFactory, "tlsFactory");
        this.http = Objects.requireNonNull(http, "http");
        IdpSslContextFactory.@Nullable ResolvedOidc resolved = tlsFactory.resolvedOidc();
        if (resolved == null) {
            throw new IllegalStateException("no IdP link on this cell — the ROPC adapter is wired on "
                    + "reverse cells only (forward cells carry no companion.*.oidc node, "
                    + "AD-12 amended 2026-08-18).");
        }
        ProxyCompanionProperties.Oidc oidc = resolved.oidc();
        // Direct construction bypasses the component @NotNull — the same named-guard reason as
        // maxInFlight/timeout below (a programmatic null fails named, not as a bare NPE in the derivation).
        this.providerUrl = Objects.requireNonNull(oidc.providerUrl(), "providerUrl");
        this.tokenEndpoint = deriveTokenEndpoint(this.providerUrl);
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
        this.adjudicationPool = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual().name("ropc-adjudication-", 0).factory());
        this.admission = new Semaphore(maxInFlight);
        this.activeAdjudications = new AtomicLong();
    }

    /**
     * In-flight adjudications (the VT-gauge seam, Story 4.1 T3): how many submitted-but-not-yet-settled
     * adjudications are on the {@code ropc-adjudication} virtual-thread pool right now. Read by the
     * observability tier's {@code ropc.adjudications.active} gauge &mdash; Micrometer's
     * {@code jvm_threads_*} binders do not count virtual threads, which is why the pool counts
     * itself. 0 at rest; never negative (rejection-compensated).
     */
    public long activeAdjudications() {
        return activeAdjudications.get();
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
            // VT-gauge seam (Story 4.1 T3): the adjudication counts as ACTIVE from submit — the inc
            // happens here, on the caller's thread, BEFORE execute, so a just-submitted adjudication
            // is never missed; the pool task's finally owns the dec. A pool rejection (shut down
            // between admission and execute) never starts the task — the catch compensates so the
            // gauge cannot leak it. Behavior is otherwise unchanged.
            activeAdjudications.incrementAndGet();
            try {
                adjudicationPool.execute(() -> {
                    try {
                        settleAdjudication(ctx, adj, tokenExchange);
                    } finally {
                        activeAdjudications.decrementAndGet();
                    }
                });
            } catch (RejectedExecutionException | IllegalStateException e) {
                activeAdjudications.decrementAndGet(); // never started — do not leak the count
                throw e;
            }
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
     * 21/22 {@code ShutdownOnFailure} subclass shape. One forked arm: the token exchange — the
     * ONLY arm since the 3.2-T4 local JWT verify was removed (Story 3.4 T2, 2026-08-27); the
     * issued-token check is a structural segment count, not a forked verification.
     * The scope is what makes the adjudication shuttable from
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
            IOException transport = transportFailure(t);
            if (transport != null && !closed) {
                // T9 (2026-08-29): the connection-error arm — an unreachable or typo'd
                // provider-url, a TLS failure, a timeout — is where the retired startup refusal
                // would have surfaced; this starred WARN is its loud successor (log-only, the
                // verdict below is unchanged). A CANCELLATION (cancelHttp/AD-32) is not a
                // provider problem and stays silent — and neither is the adapter's OWN shutdown
                // abort (close()'s hard http.close() after a drain timeout; the closed flag,
                // owner decision 2026-09-01).
                // T5 (Story 4.1 checkpoint 16): the banner is ONCE PER CONDITION — this arm keys
                // on the failure's IOException class (a dead provider is ONE condition however
                // many binds it denies); later occurrences log the one-liner. The condition is
                // NOT registered when the closed flag suppressed this occurrence — an aborted
                // shutdown bind must not spend the adapter's one banner.
                warnOperatorFailure("transport:" + transport.getClass().getName(),
                        "the token call failed at the transport layer (" + transport + ").");
            }
            return new Verdict.DenyIndeterminate();   // timeout / network error / cancel → AD-11
        }
    }

    /** The first {@link IOException} in the chain — the transport-failure test for the WARN (T9). */
    private static @Nullable IOException transportFailure(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof IOException failure) {
                return failure;
            }
        }
        return null;
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
            if ("invalid_grant".equals(error) || "invalid_client".equals(error)) {
                return new Verdict.DenyInvalid();
            }
            // Not a credential verdict — including the DAG-off flagship: Keycloak answers a
            // Direct-Access-Grants-disabled client with 400 unauthorized_client (the retired
            // startup DAG warning's runtime landing spot). T9: fail-closed deny + the operator WARN
            // (code review 2026-09-01: the parsed error rides the WARN — unauthorized_client IS
            // the DAG-off datum an operator needs).
            return unmappedStatus(response, error);
        }
        // 3xx (redirects are never followed), 403/404/429, other 4xx, 5xx — not credential verdicts.
        return unmappedStatus(response, null);
    }

    /**
     * The non-mapped-non-200 arm (T9, 2026-08-29): the verdict is unchanged fail-closed
     * {@code DenyIndeterminate}, now with the starred operator WARN naming the status (plus the
     * parsed OAuth {@code error} code on the 400 arm, when present — code review 2026-09-01), the
     * derived token endpoint, and the configured provider-url — the misconfiguration posture the
     * retired startup probe used to catch at boot. T5 (Story 4.1 checkpoint 16): the banner fires
     * once per {@code status:<code>} condition, the one-liner on repeats — the STATUS is the
     * condition (400 and 404 are two conditions, each earning its own banner). The provider-echoed
     * OAuth error string rides the per-occurrence DETAIL line only, never the condition key
     * (step-04 review, finding #6): it is provider-controlled free text, so keying on it would let
     * a provider returning distinct error strings re-fire the banner per bind and grow the
     * condition set without bound.
     */
    private Verdict unmappedStatus(HttpResponse<byte[]> response, @Nullable String oauthError) {
        String errorDetail = oauthError == null ? "" : " (OAuth error: " + oauthError + ")";
        warnOperatorFailure("status:" + response.statusCode(),
                "the token endpoint returned HTTP " + response.statusCode() + errorDetail
                        + " — not a credential verdict.");
        return new Verdict.DenyIndeterminate();
    }

    /**
     * The T5 flood bound (Story 4.1 checkpoint 16, 2026-09-03): the FULL starred banner fires on
     * the condition's FIRST occurrence, {@link #OPERATOR_WARNING_REPEAT} on every later one.
     * Log-only either way — the verdict table (AC2) is unchanged on both arms that route here.
     */
    private void warnOperatorFailure(String condition, String detail) {
        if (operatorWarnedConditions.add(condition)) {
            log.warn(OPERATOR_WARNING, detail, tokenEndpoint, providerUrl);
        } else {
            log.warn(OPERATOR_WARNING_REPEAT, detail, tokenEndpoint);
        }
    }

    /**
     * The opaque-token arm's bound warning (Story 4.1 T5 — the 2026-09-01 review's alignment row):
     * {@link #OPAQUE_TOKEN_WARNING} once per {@link #OPAQUE_TOKEN_CONDITION},
     * {@link #OPAQUE_TOKEN_WARNING_REPEAT} on repeats. Log-only — the verdict is the unchanged
     * D6 fail-closed deny either way.
     */
    private void warnOpaqueTokenIssued() {
        if (operatorWarnedConditions.add(OPAQUE_TOKEN_CONDITION)) {
            log.warn(OPAQUE_TOKEN_WARNING, tokenEndpoint, providerUrl);
        } else {
            log.warn(OPAQUE_TOKEN_WARNING_REPEAT, tokenEndpoint);
        }
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
     * The AC2 issued-token dispatch (amended by Story 3.4 T1/T2, 2026-08-27). A 200 body must
     * carry an {@code access_token}; the token is checked ONLY structurally: exactly three
     * {@code '.'}-separated segments (a JWS) is the provider's &quot;issues JWT access
     * tokens&quot; requirement satisfied — {@code Allow}, derived from the endpoint verdict alone
     * (D7: no signature verification, no claim checks, no provider-key fetch). Anything else is a
     * non-JWT (opaque) token &rarr; the D6 fail-closed deny (there is no second wire arm to ask).
     * The segment count is deliberately library-free — no Nimbus type touches the token.
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
            // T5 (Story 4.1 checkpoint 16): the WARN is bounded like the operator banner — full
            // policy warning once, one-liner per repeat — and now carries the derived endpoint
            // and provider-url (the multi-cell context the 2026-09-01 review flagged missing).
            warnOpaqueTokenIssued();
            return new Verdict.DenyIndeterminate();
        }
        // D7 (Story 3.4 T2, 2026-08-27): the TLS client-authenticated provider link is the sole
        // trust anchor — the proxy is this token's only consumer, so nothing re-proves the
        // provider's signature locally. Content past the segment count is never parsed.
        return new Verdict.Allow();
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
        return HttpRequest.newBuilder(tokenEndpoint)   // DERIVED from provider-url (T9) — no discovery fetch
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
     * The T7 AD-22 stop body (invoked by {@link AdjudicationLifecycle}; also the inferred destroy
     * method — idempotent, the failed-boot backstop). Order: <b>deny in-flight FIRST</b> —
     * {@code shutdownNow()} interrupts every pool task (each settles its pin fail-closed in its
     * catch) and {@code awaitTermination} bounds the drain at the per-request budget + 1s, logging
     * fail-closed and proceeding on timeout (the hard close below aborts whatever exchanges
     * remain, and every aborted join settles {@code DenyIndeterminate}) — <b>then</b> the shared
     * client and the client secret are released. (The 3.2-era key-cache-refresh-before-client-close
     * step died with the cache — Story 3.4 T2, 2026-08-27; the pool and the one shared client are
     * the adapter's whole executor surface now, AD-28.)
     */
    @Override
    public void close() {
        closed = true;   // our own aborts are not provider problems — keep the operator WARN off them
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
        http.close();
        clientSecret.zeroize();   // AD-10: the adapter's own secret material
    }
}
