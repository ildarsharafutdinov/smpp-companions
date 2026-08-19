package smpp.companion.proxy.security;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.extern.slf4j.Slf4j;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Story 3.2 T4 (AC3) — the cached JWKS the production adapter's local JWT defense-in-depth verifies
 * against. Cache-and-refresh ONLY (AD-12): the public keys are cached, verdicts never are, and the
 * bind path NEVER fetches in the foreground — it reads the cached {@link JWKSet} and, on a {@code kid}
 * miss, denies now and asks this cache to refresh in the background (no refresh-and-retry).
 *
 * <p><b>The cache invariant (deferred-work &sect;2.1 item 6b).</b> The single {@code AtomicReference}
 * is swapped <b>whole</b> on a successful refresh — a 200 that parses and carries at least one key —
 * and is <b>never nulled anywhere</b>: a failed refresh retains the last good set (the ratified
 * slice's unconditional invalidation-on-miss is exactly the bug this productionizes away). A set is
 * also never evicted for AGE: staleness is bounded operationally by the refresh cadence, not by
 * dropping keys an unknown-kid attacker could then not even be checked against — an empty cache is
 * strictly worse than a stale one, because <i>every</i> bind would deny indeterminately while it
 * lasted (fail-closed, but broken — the zero-admitted-capacity hazard).
 *
 * <p><b>The refresh scheduler (AD-28(2), &sect;2.1 item 6a).</b> A hand-rolled scheduled executor
 * over a single named virtual thread — NOT {@code @Scheduled}, and NOT the adjudication pool or its
 * admission semaphore: refreshes must neither consume bind-admission permits (bind saturation must
 * not block key-rotation recovery) nor be starvable by binds. The single-threaded scheduler also
 * serializes refreshes, which is the single-flight bound — a kid-miss trigger never piles up fetches.
 * The initial refresh fires at construction (background: a cold cache denies fail-closed until it
 * lands — a transient JWKS outage is a runtime condition, not the startup refusal discovery is);
 * afterwards the cadence is refresh-ahead at <b>half the TTL</b> (dev-selected default, the
 * spine-deferred value), so one failed refresh leaves another half-TTL window before the set
 * reaches its nominal age.
 *
 * <p><b>Lifecycle (AD-22).</b> {@link #close()} stops the refresh FIRST — the adapter's shutdown
 * order is refresh-stop &rarr; pool &rarr; shared client, so no in-flight refresh races the closing
 * client. JWKS material is PUBLIC (no zeroization obligation — AD-10 covers secrets, not public keys).
 */
@Slf4j
final class JwksCache implements AutoCloseable {

    /** Never null after a successful refresh; the ONLY write site is {@link #refresh()}'s whole swap. */
    private final AtomicReference<@Nullable JWKSet> keys = new AtomicReference<>();

    private final HttpClient http;
    private final URI jwksUri;
    private final Duration requestTimeout;
    private final ScheduledExecutorService refreshScheduler;

    @SuppressWarnings("FutureReturnValueIgnored")   // reason: the periodic task's ScheduledFuture is
    // intentionally discarded — refresh() is fully guarded (nothing escapes it), and cancellation is
    // wholesale via shutdownNow() in close(), never per-task (2-2 class-suppression precedent).
    JwksCache(HttpClient http, URI jwksUri, Duration ttl, Duration requestTimeout) {
        this.http = Objects.requireNonNull(http, "http");
        this.jwksUri = Objects.requireNonNull(jwksUri, "jwksUri");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
        Objects.requireNonNull(ttl, "ttl");
        if (ttl.isZero() || ttl.isNegative()) {
            // Direct construction bypasses the @DurationMin(nanos = 1) annotation; a non-positive TTL
            // degenerates the refresh-ahead interval — the typed capacity guard, max-in-flight precedent.
            throw new IllegalArgumentException(
                    "oidc.jwks-cache-ttl must be positive (AD-28(2)) — refusing to construct.");
        }
        this.refreshScheduler = Executors.newScheduledThreadPool(1,
                Thread.ofVirtual().name("jwks-refresh-", 0).factory());
        Duration interval = ttl.dividedBy(2);   // refresh-ahead: half the TTL leaves a retry window
        if (!interval.isPositive()) {
            interval = Duration.ofMillis(1);   // scheduleWithFixedDelay rejects a zero period
        }
        refreshScheduler.scheduleWithFixedDelay(this::refresh, 0, interval.toNanos(), TimeUnit.NANOSECONDS);
    }

    /**
     * The cached set — read-only on the bind path. {@code null} means the initial refresh has not
     * landed yet (cold cache): the caller denies fail-closed and asks for a refresh, it never waits.
     */
    @Nullable
    JWKSet current() {
        return keys.get();
    }

    /**
     * The kid-miss (and cold-cache) trigger: one <b>out-of-band</b> refresh, enqueued on this cache's
     * own scheduler. Returns immediately — the verdict that called it has already settled deny. The
     * single scheduler thread serializes this with the periodic cycle (the single-flight bound); it
     * shares nothing with the adjudication pool or its admission semaphore (&sect;2.1 item 6a).
     */
    void requestRefresh() {
        refreshScheduler.execute(this::refresh);
    }

    /**
     * One refresh cycle, fully guarded: a periodic task that threw would suppress every LATER run
     * of the {@code scheduleWithFixedDelay} schedule, so nothing escapes. Every failure retains the
     * cached set (&sect;2.1 item 6b); success swaps the new set in whole.
     */
    private void refresh() {
        try {
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder(jwksUri).timeout(requestTimeout).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.warn("JWKS refresh at {} returned HTTP {} — retaining the cached set (AD-11 fail-closed).",
                        jwksUri, response.statusCode());
                return;
            }
            JWKSet fetched = JWKSet.parse(response.body());
            if (fetched.getKeys().isEmpty()) {
                log.warn("JWKS refresh at {} returned an EMPTY key set — treating it as provider "
                        + "misbehavior, retaining the cached set (AD-11 fail-closed).", jwksUri);
                return;
            }
            keys.set(fetched);   // the ONLY write: a whole swap on success — never nulled anywhere
        } catch (InterruptedException e) {
            // shutdownNow() landed mid-refresh (close, AD-22) — restore the interrupt and give up
            Thread.currentThread().interrupt();
        } catch (IOException | ParseException e) {
            log.warn("JWKS refresh at {} failed ({}: {}) — retaining the cached set (AD-11 fail-closed).",
                    jwksUri, e.getClass().getSimpleName(), e.getMessage());
        }
    }

    /** Stops the refresh scheduler. The adapter calls this FIRST in its shutdown (AD-22 ordering). */
    @Override
    public void close() {
        refreshScheduler.shutdownNow();
    }
}
