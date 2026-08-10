package smpp.companion.proxy.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Story 2.1 Task 4 — the <b>always-on</b> fail-closed guards in {@link RopcSlice} that the live (Docker-gated) suite
 * cannot keep biting in CI, driven through the real {@link BindCredentialVerifier#verify} port against an in-process
 * {@link HttpServer} stand-in IdP (no container, no network). Covers AC2 path-4 (the 4xx/5xx {@code mapNon200}
 * collapse), AC2 path-2 (introspection {@code active:false} / non-200 deny), AC5 (password zeroization on completion
 * AND on saturation), and AC6 / AD-28(4) (the bounded-pool saturation fail-closed deny).
 *
 * <p><b>Why an in-process IdP:</b> {@code mapNon200} and the saturation admission gate are private to the slice; the
 * only way to drive them deterministically is to control the token endpoint's status and latency. The
 * {@link HttpServer} serves {@code /token} (status/latency per test) + {@code /certs} (a fixed parseable JWKS, so the
 * STS fan-out's JWKS subtask always succeeds and the token status is what decides the verdict) + optionally
 * {@code /introspect}. Plain HTTP, loopback — exactly the shape {@link RopcSliceCancelTest} proved out for AC3.
 *
 * <p><b>RED-on-neuter (AC9 / AI-1):</b> every assertion below is load-bearing — neuter the matching guard in
 * {@link RopcSlice} (the 4xx/5xx branch, the introspection active/non-200 check, the completion/saturation
 * {@code zeroize()}, the {@code admission.tryAcquire()} gate) and the corresponding test goes RED.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-11/AD-12 RopcSlice — fail-closed + zeroization + saturation (always-on; in-process IdP)")
class RopcSliceFailClosedTest {

    private static final String REALM = "/realms/x";
    private static final String TOKEN_PATH = REALM + "/protocol/openid-connect/token";
    private static final String CERTS_PATH = REALM + "/protocol/openid-connect/certs";
    private static final String INTROSPECT_PATH = REALM + "/protocol/openid-connect/token/introspect";

    /** A parseable JWKS body so the slice's concurrent JWKS fetch always succeeds (the token status decides). */
    private static final String JWKS_BODY = jwksBody();

    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    private static String jwksBody() {
        try {
            RSAKey key = new RSAKeyGenerator(2048).keyID("present").generate();
            return new JWKSet(key.toPublicJWK()).toString();
        } catch (Exception e) {
            throw new IllegalStateException("could not build JWKS body", e);
        }
    }

    private static BindCredential cred(AsciiString password) {
        return new BindCredential(new SystemId(new AsciiString("testuser")), new Password(password));
    }

    /** Drives the port with the RequestContext bound via ScopedValue (models real relay usage). */
    private static VerdictRequest verify(RopcSlice slice, BindCredential credential) throws Exception {
        RequestContext rc = new RequestContext(
                credential.systemId(), DefaultChannelId.newInstance(), Instant.now().plusSeconds(15));
        return ScopedValue.where(CTX, rc).call(() -> slice.verify(credential, CTX));
    }

    private static Verdict awaitVerdict(VerdictRequest req) throws Exception {
        return req.future().get(15, TimeUnit.SECONDS);
    }

    private static RopcSlice slice(HttpServer server, boolean introspect, int maxInflight) {
        String base = "http://127.0.0.1:" + server.getAddress().getPort() + REALM;
        HttpClient http = HttpClient.newHttpClient();   // plain HTTP stand-in IdP (no mTLS)
        return new RopcSlice(http, new RopcSlice.SliceConfig(
                URI.create(base + "/protocol/openid-connect/token"),
                URI.create(base + "/protocol/openid-connect/token/introspect"),
                URI.create(base + "/protocol/openid-connect/certs"),
                base, "smpp-client", "secret", false, introspect), maxInflight);
    }

    private static RopcSlice slice(HttpServer server, boolean introspect) {
        return slice(server, introspect, 4);
    }

    /** Stands up the IdP: {@code tokenHandler} on /token, a fixed JWKS on /certs, and optional /introspect. */
    private static HttpServer newServer(HttpHandler tokenHandler, HttpHandler introspectHandler) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext(TOKEN_PATH, tokenHandler);
        server.createContext(CERTS_PATH, RopcSliceFailClosedTest::handleCerts);
        if (introspectHandler != null) {
            server.createContext(INTROSPECT_PATH, introspectHandler);
        }
        server.start();
        return server;
    }

    private static void handleCerts(HttpExchange exchange) throws IOException {
        sendJson(exchange, 200, JWKS_BODY);
    }

    private static void sendJson(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void drainBody(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
    }

    // ── AC2 path-4: the 4xx/5xx mapNon200 collapse (always-on; live suite only covers 400/401 via Docker) ──────

    @Test
    @DisplayName("token endpoint 401 → DenyInvalid (AD-11 4xx≠200 mapping; always-on)")
    void tokenEndpoint4xx_yieldsDenyInvalid() throws Exception {
        HttpServer server = newServer(ex -> {
            drainBody(ex);
            sendJson(ex, 401, "{\"error\":\"invalid_client\"}");
        }, null);
        try (RopcSlice slice = slice(server, false)) {
            Verdict v = awaitVerdict(verify(slice, cred(new AsciiString("pw"))));
            assertThat(v).as("4xx token response → DenyInvalid (AD-11)").isInstanceOf(Verdict.DenyInvalid.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("token endpoint 500 → DenyIndeterminate (AD-11 non-4xx fail-closed)")
    void tokenEndpoint5xx_yieldsDenyIndeterminate() throws Exception {
        HttpServer server = newServer(ex -> {
            drainBody(ex);
            sendJson(ex, 500, "{\"error\":\"server_error\"}");
        }, null);
        try (RopcSlice slice = slice(server, false)) {
            Verdict v = awaitVerdict(verify(slice, cred(new AsciiString("pw"))));
            assertThat(v).as("5xx token response → DenyIndeterminate (AD-11)").isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    // ── AC2 path-2: RFC 7662 introspection deny branches (active:false / non-200) ──────────────────────────────

    @Test
    @DisplayName("introspection active:false → DenyIndeterminate (RFC 7662 fail-closed; always-on)")
    void introspectionInactive_yieldsDenyIndeterminate() throws Exception {
        HttpServer server = newServer(
                ex -> { drainBody(ex); sendJson(ex, 200, "{\"access_token\":\"opaque\",\"token_type\":\"Bearer\"}"); },
                ex -> { drainBody(ex); sendJson(ex, 200, "{\"active\":false}"); });
        try (RopcSlice slice = slice(server, true)) {
            Verdict v = awaitVerdict(verify(slice, cred(new AsciiString("pw"))));
            assertThat(v).as("introspection active:false → DenyIndeterminate (AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("introspection non-200 → DenyIndeterminate (RFC 7662 fail-closed; always-on)")
    void introspectionNon200_yieldsDenyIndeterminate() throws Exception {
        // The 500 body carries active:true on purpose: if the != 200 guard were dropped, the slice would parse it and
        // return Allow — so this test only stays GREEN while the non-200 deny guard fires (RED-on-neuter).
        HttpServer server = newServer(
                ex -> { drainBody(ex); sendJson(ex, 200, "{\"access_token\":\"opaque\",\"token_type\":\"Bearer\"}"); },
                ex -> { drainBody(ex); sendJson(ex, 500, "{\"active\":true}"); });
        try (RopcSlice slice = slice(server, true)) {
            Verdict v = awaitVerdict(verify(slice, cred(new AsciiString("pw"))));
            assertThat(v).as("introspection non-200 → DenyIndeterminate (AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    // ── AC5 / AD-12: password zeroization through the slice ────────────────────────────────────────────────────

    @Test
    @DisplayName("password backing array is zeroized after adjudication completes (AC5/AD-12; RED-on-neuter)")
    void passwordZeroizedAfterAdjudication() throws Exception {
        HttpServer server = newServer(ex -> {
            drainBody(ex);
            sendJson(ex, 401, "{}");   // any outcome — the finally-block zeroize is what we assert
        }, null);
        AsciiString raw = new AsciiString("s3cret");   // shared backing — Password does not copy (AC5 coverage)
        BindCredential credential = cred(raw);
        try (RopcSlice slice = slice(server, false)) {
            awaitVerdict(verify(slice, credential));   // DenyInvalid; the pool thread's finally zeroizes next
            // The slice zeroizes in the finally AFTER pin.complete, so a brief bounded poll closes the tiny race
            // between the test thread unblocking on future().get() and the pool thread running zeroize().
            assertWipedSoon(raw, Duration.ofSeconds(2));
        } finally {
            server.stop(0);
        }
    }

    // ── AC6 / AD-28(4): bounded-pool saturation fails closed ───────────────────────────────────────────────────

    @Test
    @DisplayName("saturation: a pool at capacity denies a 2nd bind DenyIndeterminate immediately + zeroizes (AC6)")
    void saturation_deniesWithoutWork_andZeroizes() throws Exception {
        CountDownLatch requestReceived = new CountDownLatch(1);
        CountDownLatch holdPermit = new CountDownLatch(1);   // keeps verify#1 in-flight → the lone permit stays held
        HttpServer server = newServer(ex -> {
            try {
                requestReceived.countDown();
                drainBody(ex);
                holdPermit.await();
                sendJson(ex, 401, "{}");   // released → verify#1 resolves DenyInvalid
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (IOException ioe) {
                // verify#2 cancels its exchange; the late write after release may fail — expected.
            }
        }, null);

        AsciiString pw1 = new AsciiString("pw1");
        AsciiString pw2 = new AsciiString("pw2");
        try (RopcSlice slice = slice(server, false, 1)) {   // maxInflight = 1
            VerdictRequest first = verify(slice, cred(pw1));   // acquires the single permit, blocks at holdPermit
            assertTrue(requestReceived.await(5, TimeUnit.SECONDS), "verify#1 should reach the slow IdP (permit held)");

            // The assertions live in a try/finally so holdPermit is ALWAYS released — even if a RED-on-neuter
            // mutation makes second.future() time out (a stranded handler thread would otherwise hang the test JVM).
            try {
                long start = System.nanoTime();
                VerdictRequest second = verify(slice, cred(pw2));   // permit exhausted → fail-closed deny, no work
                Verdict v2 = second.future().get(2, TimeUnit.SECONDS);
                long elapsedMs = (System.nanoTime() - start) / 1_000_000;

                assertThat(v2).as("a saturated pool denies a 2nd bind DenyIndeterminate (AD-11/AD-28(4))")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
                assertThat(elapsedMs).as("saturation must DENY without starting work (AC6)").isLessThan(1_000L);
                // Saturation-path zeroize (RopcSlice.verify line 120) runs on the caller thread before verify returns —
                // race-free: pw2 is already wiped the instant verify(slice, cred(pw2)) completed.
                assertThat(isAllZero(pw2)).as("the saturated/denied bind's password is zeroized (AC5)").isTrue();
            } finally {
                holdPermit.countDown();   // ALWAYS release the in-flight IdP handlers so the test unwinds cleanly
            }
            awaitVerdict(first);   // DenyInvalid after release (drain the pool thread before close)
        } finally {
            server.stop(0);
        }
    }

    // ── AC6: admission-capacity fail-fast (constructor precondition; the audit's uncovered admission guard) ─────

    @Test
    @DisplayName("maxInflight < 1 is rejected at construction (AC6 admission-capacity fail-fast; RED-on-neuter)")
    void maxInflightBelowOne_isRejectedAtConstruction() {
        URI any = URI.create("http://127.0.0.1:1" + REALM + "/protocol/openid-connect/token");
        RopcSlice.SliceConfig cfg = new RopcSlice.SliceConfig(
                any, any, any, "http://127.0.0.1" + REALM, "c", "s", false, false);
        // maxInflight=0: WITHOUT this guard, Semaphore(0) is valid and EVERY bind silently denies DenyIndeterminate
        // (fail-closed but broken/misconfigured) — the guard is the typed admission-capacity fail-fast.
        assertThatThrownBy(() -> new RopcSlice(HttpClient.newHttpClient(), cfg, 0))
                .isInstanceOf(IllegalArgumentException.class);
        // maxInflight<0 is independently caught by Semaphore's own constructor too, but the guard is the explicit
        // typed boundary; assert both document the intent.
        assertThatThrownBy(() -> new RopcSlice(HttpClient.newHttpClient(), cfg, -1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ── helpers ───────────────────────────────────────────────────────────────────────────────────────────────

    private static boolean isAllZero(AsciiString value) {
        byte[] array = value.array();
        int offset = value.arrayOffset();
        for (int i = 0; i < value.length(); i++) {
            if (array[offset + i] != 0) {
                return false;
            }
        }
        return true;
    }

    private static void assertWipedSoon(AsciiString value, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (isAllZero(value)) {
                return;
            }
            Thread.sleep(2);
        }
        assertThat(isAllZero(value))
                .as("password backing array must be zeroized after adjudication (AC5/AD-12)")
                .isTrue();
    }
}
