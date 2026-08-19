package smpp.companion.proxy.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Story 3.2 T4 (AC3) — the {@link JwksCache} component contract, asserted directly (the adapter
 * exposes it package-private for exactly this, the slice's {@code verifyWithJwks} precedent): the
 * cache is swapped WHOLE on successful refresh and is <b>never nulled before a successful fetch</b>
 * (deferred-work &sect;2.1 item 6b — the slice's unconditional invalidation is the bug this
 * productionizes away); the refresh runs on the cache's OWN scheduler, never the adjudication pool
 * or its admission semaphore (&sect;2.1 item 6a); a {@code kid} miss schedules one out-of-band
 * refresh; close stops the refresh (AD-22's refresh-before-cache ordering starts here). The stand-in
 * is a plain-HTTP {@link HttpServer} — the component takes any {@link HttpClient}/URI pair, and the
 * TLS leg of the real refresh is already exercised end-to-end by the adapter suite.
 *
 * <p><b>RED-on-neuter (AI-1):</b> each row bites one named guard — revert the swap to the slice's
 * {@code set(null)}-on-invalidation and {@code failedRefreshRetainsLastGoodSet} goes RED; drop the
 * empty-set guard and {@code emptyKeySetIsNotSwapped} goes RED; route the kid-miss trigger through
 * the adjudication pool and the refresh starves under saturation (pinned in the adapter suite).
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-12/AD-28(2) JwksCache — whole-swap-only cache + isolated refresh scheduler")
class JwksCacheTest {

    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(2);

    /** A stand-in JWKS endpoint whose served body and status flip via {@link Refreshee#body}/{@code status}. */
    private static final class Refreshee implements HttpHandler {
        final AtomicInteger hits = new AtomicInteger();
        final AtomicReference<String> body = new AtomicReference<>();
        volatile int status = 200;

        @Override
        public void handle(HttpExchange ex) throws IOException {
            hits.incrementAndGet();
            ex.getRequestBody().readAllBytes();
            if (status != 200) {
                ex.sendResponseHeaders(status, -1);
                ex.close();
                return;
            }
            byte[] bytes = body.get().getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(bytes);
            }
        }
    }

    // ── the cache contract ─────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("the initial refresh populates the cache (background, at construction)")
    void initialRefreshPopulatesCache() throws Exception {
        RSAKey key = key("k1");
        Refreshee endpoint = new Refreshee();
        endpoint.body.set(jwksBody(key));
        HttpServer server = standIn(endpoint);
        try (JwksCache cache = new JwksCache(HttpClient.newHttpClient(), uri(server),
                Duration.ofMinutes(5), CALL_TIMEOUT)) {
            JWKSet cached = awaitKeys(cache);
            assertThat(cached.getKeyByKeyId("k1")).as("the fetched set is served").isNotNull();
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("a failed refresh (non-200, then unparseable body) RETAINS the last good set — never nulled (§2.1 item 6b)")
    void failedRefreshRetainsLastGoodSet() throws Exception {
        Refreshee endpoint = new Refreshee();
        endpoint.body.set(jwksBody(key("k1")));
        HttpServer server = standIn(endpoint);
        try (JwksCache cache = new JwksCache(HttpClient.newHttpClient(), uri(server),
                Duration.ofMinutes(5), CALL_TIMEOUT)) {
            awaitKeys(cache);   // populated by the initial refresh

            endpoint.status = 500;   // refresh fails at the status line
            cache.requestRefresh();
            awaitHits(endpoint, 2);
            assertThat(cache.current()).as("a non-200 refresh must not evict the cached set (§6b)")
                    .isNotNull()
                    .extracting(k -> k.getKeyByKeyId("k1"))
                    .isNotNull();

            endpoint.status = 200;
            endpoint.body.set("<html>captive portal</html>");   // 200-but-garbage fails at parse
            cache.requestRefresh();
            awaitHits(endpoint, 3);
            assertThat(cache.current()).as("an unparseable refresh must not evict the cached set (§6b)")
                    .isNotNull()
                    .extracting(k -> k.getKeyByKeyId("k1"))
                    .isNotNull();
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("a successful refresh swaps the set WHOLE (rotated-out kids disappear, not accumulate)")
    void successfulRefreshSwapsWholeSet() throws Exception {
        Refreshee endpoint = new Refreshee();
        endpoint.body.set(jwksBody(key("k1")));
        HttpServer server = standIn(endpoint);
        try (JwksCache cache = new JwksCache(HttpClient.newHttpClient(), uri(server),
                Duration.ofMinutes(5), CALL_TIMEOUT)) {
            awaitKeys(cache);

            endpoint.body.set(jwksBody(key("k2")));   // key rotation: k1 gone, k2 in
            cache.requestRefresh();
            awaitHits(endpoint, 2);
            assertThat(cache.current()).as("the refreshed set carries the NEW kid")
                    .isNotNull()
                    .extracting(k -> k.getKeyByKeyId("k2"))
                    .isNotNull();
            assertThat(cache.current().getKeyByKeyId("k1"))
                    .as("the swap is whole — a rotated-OUT kid must not survive (a stale key is a verification hazard)")
                    .isNull();
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("an empty key set is treated as provider misbehavior, not a successful swap")
    void emptyKeySetIsNotSwapped() throws Exception {
        Refreshee endpoint = new Refreshee();
        endpoint.body.set(jwksBody(key("k1")));
        HttpServer server = standIn(endpoint);
        try (JwksCache cache = new JwksCache(HttpClient.newHttpClient(), uri(server),
                Duration.ofMinutes(5), CALL_TIMEOUT)) {
            awaitKeys(cache);

            endpoint.body.set("{\"keys\":[]}");
            cache.requestRefresh();
            awaitHits(endpoint, 2);
            assertThat(cache.current()).as("an empty JWKS must not empty the cache")
                    .isNotNull()
                    .extracting(k -> k.getKeyByKeyId("k1"))
                    .isNotNull();
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("the periodic (TTL refresh-ahead) refresh swaps without any bind or kid miss")
    void periodicRefreshSwapsSet() throws Exception {
        Refreshee endpoint = new Refreshee();
        endpoint.body.set(jwksBody(key("k1")));
        HttpServer server = standIn(endpoint);
        try (JwksCache cache = new JwksCache(HttpClient.newHttpClient(), uri(server),
                Duration.ofMillis(200), CALL_TIMEOUT)) {   // refresh-ahead interval = TTL/2 = 100ms
            awaitKeys(cache);
            endpoint.body.set(jwksBody(key("k2")));
            awaitCondition("the TTL/2 refresh-ahead cycle picks up the rotated key",
                    () -> cache.current() != null && cache.current().getKeyByKeyId("k2") != null);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("close() stops the refresh scheduler (AD-22: refresh stops before the cache goes away)")
    void closeStopsTheRefreshScheduler() throws Exception {
        Refreshee endpoint = new Refreshee();
        endpoint.body.set(jwksBody(key("k1")));
        HttpServer server = standIn(endpoint);
        JwksCache cache = new JwksCache(HttpClient.newHttpClient(), uri(server),
                Duration.ofMillis(100), CALL_TIMEOUT);
        try {
            awaitKeys(cache);   // initial refresh done
        } finally {
            cache.close();
        }
        int hitsAtClose = endpoint.hits.get();
        Thread.sleep(400);   // ≥ 3 nominal refresh intervals
        assertThat(endpoint.hits.get())
                .as("no refresh may fire after close (a closed-scheduler refresh would race the closing client)")
                .isEqualTo(hitsAtClose);
        server.stop(0);
    }

    @Test
    @DisplayName("constructor fail-fast: a non-positive jwks-cache-ttl refuses construction (the T3 typed-guard pattern)")
    void nonPositiveTtlRefusesConstruction() throws Exception {
        HttpServer server = standIn(new Refreshee());
        try {
            assertThatThrownBy(() -> new JwksCache(HttpClient.newHttpClient(), uri(server),
                    Duration.ZERO, CALL_TIMEOUT))
                    .as("ttl=0 would make the refresh-ahead interval degenerate")
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> new JwksCache(HttpClient.newHttpClient(), uri(server),
                    Duration.ofSeconds(-1), CALL_TIMEOUT))
                    .as("a negative ttl is not a TTL")
                    .isInstanceOf(IllegalArgumentException.class);
        } finally {
            server.stop(0);
        }
    }

    // ── fixtures ──────────────────────────────────────────────────────────────────────────────

    private static RSAKey key(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException("could not generate RSA key", e);
        }
    }

    private static String jwksBody(RSAKey publicKey) {
        return JSONObjectUtils.toJSONString(new JWKSet(List.of(publicKey.toPublicJWK())).toJSONObject(true));
    }

    private static HttpServer standIn(Refreshee endpoint) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/certs", endpoint);
        server.start();
        return server;
    }

    private static URI uri(HttpServer server) {
        return URI.create("http://localhost:" + server.getAddress().getPort() + "/certs");
    }

    private static JWKSet awaitKeys(JwksCache cache) {
        awaitCondition("the initial JWKS refresh", () -> cache.current() != null);
        return cache.current();
    }

    private static void awaitHits(Refreshee endpoint, int expected) {
        awaitCondition("JWKS hit #" + expected, () -> endpoint.hits.get() >= expected);
    }

    /** Polls {@code condition} every 10ms up to 5s — the async refresh lands on its own scheduler. */
    private static void awaitCondition(String what, java.util.function.BooleanSupplier condition) {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while awaiting " + what, e);
            }
        }
        throw new IllegalStateException("timed out awaiting " + what);
    }
}
