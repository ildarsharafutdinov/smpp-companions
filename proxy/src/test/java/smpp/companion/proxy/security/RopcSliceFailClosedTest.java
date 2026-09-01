package smpp.companion.proxy.security;

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
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Story 2.1 Task 4 — the <b>always-on</b> fail-closed guards in {@link RopcSlice} that the live (Docker-gated) suite
 * cannot keep biting in CI, driven through the real {@link BindCredentialVerifier#verify} port against an in-process
 * {@link HttpServer} stand-in IdP (no container, no network). Covers the non-200 {@code mapNon200} collapse (4xx
 * vs 5xx), the AMENDED-CONTRACT token arms (Story 3.4 T8, 2026-08-29): the D6 pin — a 200 opaque (non-three-segment)
 * token denies fail-closed — and the D7 pin — a 200 three-segment garbage token {@code Allow}s because the verdict
 * derives from the token-endpoint response ALONE (nothing local parses or verifies the token; reintroducing any
 * local check goes RED here); AC5 (password zeroization on completion AND on saturation); and AC6 / AD-28(4) (the
 * bounded-pool saturation fail-closed deny). The slice's 2.1-era interop arms (local JWKS verify, RFC 7662
 * introspection, mTLS client auth) were REMOVED everywhere by Story 3.4 T8 — their rows retired with them, and the
 * mandatory-{@code client_secret} config guard (their successor as the config's fail-fast) is pinned below.
 *
 * <p><b>Why an in-process IdP:</b> {@code mapNon200} and the saturation admission gate are private to the slice; the
 * only way to drive them deterministically is to control the token endpoint's status and latency. The
 * {@link HttpServer} serves {@code /token} (status/body/latency per test). Plain HTTP, loopback — exactly the shape
 * {@link RopcSliceCancelTest} proved out for AC3.
 *
 * <p><b>RED-on-neuter (AC9 / AI-1):</b> every assertion below is load-bearing — neuter the matching guard in
 * {@link RopcSlice} (the 4xx/5xx branch, the three-segment gate in either direction, the completion/saturation
 * {@code zeroize()}, the {@code admission.tryAcquire()} gate, the {@code clientSecret} null guard) and the
 * corresponding test goes RED.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-11/AD-12 RopcSlice — fail-closed + zeroization + saturation (always-on; in-process IdP)")
class RopcSliceFailClosedTest {

    private static final String REALM = "/realms/x";
    private static final String TOKEN_PATH = REALM + "/protocol/openid-connect/token";

    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

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

    private static RopcSlice slice(HttpServer server, int maxInflight) {
        String base = "http://127.0.0.1:" + server.getAddress().getPort() + REALM;
        HttpClient http = HttpClient.newHttpClient();   // plain HTTP stand-in IdP (transport TLS is the live suite's)
        return new RopcSlice(http, new RopcSlice.SliceConfig(
                URI.create(base + "/protocol/openid-connect/token"),
                "smpp-client", "secret"), maxInflight);
    }

    private static RopcSlice slice(HttpServer server) {
        return slice(server, 4);
    }

    /** Stands up the IdP: {@code tokenHandler} on /token (the slice's only wire call — Story 3.4 T8). */
    private static HttpServer newServer(HttpHandler tokenHandler) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext(TOKEN_PATH, tokenHandler);
        server.start();
        return server;
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

    // ── the 4xx/5xx mapNon200 collapse (always-on; live suite covers the same arms via Docker) ────────────────

    @Test
    @DisplayName("token endpoint 401 → DenyInvalid (AD-11 4xx≠200 mapping; always-on)")
    void tokenEndpoint4xx_yieldsDenyInvalid() throws Exception {
        HttpServer server = newServer(ex -> {
            drainBody(ex);
            sendJson(ex, 401, "{\"error\":\"invalid_client\"}");
        });
        try (RopcSlice slice = slice(server)) {
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
        });
        try (RopcSlice slice = slice(server)) {
            Verdict v = awaitVerdict(verify(slice, cred(new AsciiString("pw"))));
            assertThat(v).as("5xx token response → DenyIndeterminate (AD-11)").isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    // ── the amended-contract token arms (Story 3.4 T8, 2026-08-29; D6/D7-aligned, through the real port) ──────

    @Test
    @DisplayName("D6: 200 + opaque (non-three-segment) token → DenyIndeterminate (JWT-only; no second wire arm)")
    void opaqueToken_yieldsDenyIndeterminate() throws Exception {
        // 200 with an opaque token: not adjudicable, and there is no introspection arm to ask (removed with the
        // slice's 7662 arm, Story 3.4 T8) — the deny is provably the policy gate. Neuter the segment-count check
        // (always-allow) and this row goes RED.
        HttpServer server = newServer(ex -> {
            drainBody(ex);
            sendJson(ex, 200, "{\"access_token\":\"opaque-token-without-separators\",\"token_type\":\"Bearer\"}");
        });
        try (RopcSlice slice = slice(server)) {
            Verdict v = awaitVerdict(verify(slice, cred(new AsciiString("pw"))));
            assertThat(v).as("an opaque token is not adjudicable → DenyIndeterminate (D6, AD-11 fail-closed)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("D7: 200 + three-segment GARBAGE token → Allow — the verdict is the endpoint's alone (nothing local parses it)")
    void threeSegmentGarbageToken_yieldsAllow() throws Exception {
        // Three dot-separated segments of base64 garbage: structurally a JWS, cryptographically worthless. It must Allow —
        // the token-endpoint response (over the TLS provider link) is the sole trust anchor. Reintroduce ANY local
        // check (signature, kid, claims — the retired 2.1 arms) and this row goes RED.
        HttpServer server = newServer(ex -> {
            drainBody(ex);
            sendJson(ex, 200, "{\"access_token\":\"aaa.bbb.ccc\",\"token_type\":\"Bearer\"}");
        });
        try (RopcSlice slice = slice(server)) {
            Verdict v = awaitVerdict(verify(slice, cred(new AsciiString("pw"))));
            assertThat(v).as("a three-segment token Allows on the endpoint verdict alone (D7)")
                    .isEqualTo(new Verdict.Allow());
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("the structural gate's segment-count BOUNDARIES: 2- and 4-segment tokens deny fail-closed "
            + "(D6) — only EXACTLY three segments Allows (the production suite's twin row's shape)")
    void segmentCountBoundariesDenyFailClosed() throws Exception {
        // Chunk-B review 2026-09-01: the slice's D6/D7 rows drove only 0- and 3-segment shapes, so a
        // neutered gate (segments < 3 / >= 3 / "more than one dot") stayed green in this tier too.
        // Mirrors RopcBindCredentialVerifierTest.segmentCountBoundariesDenyFailClosed.
        HttpServer fourSegment = newServer(ex -> {
            drainBody(ex);
            sendJson(ex, 200, "{\"access_token\":\"a.b.c.d\",\"token_type\":\"Bearer\"}");
        });
        try (RopcSlice slice = slice(fourSegment)) {
            Verdict v = awaitVerdict(verify(slice, cred(new AsciiString("pw"))));
            assertThat(v).as("a 4-segment (JWE-shaped) token is not a three-segment JWS — D6 fail-closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            fourSegment.stop(0);
        }
        HttpServer twoSegment = newServer(ex -> {
            drainBody(ex);
            sendJson(ex, 200, "{\"access_token\":\"a.b\",\"token_type\":\"Bearer\"}");
        });
        try (RopcSlice slice = slice(twoSegment)) {
            Verdict v = awaitVerdict(verify(slice, cred(new AsciiString("pw"))));
            assertThat(v).as("a 2-segment token is not a three-segment JWS — D6 fail-closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            twoSegment.stop(0);
        }
    }

    // ── AC5 / AD-12: password zeroization through the slice ────────────────────────────────────────────────────

    @Test
    @DisplayName("password backing array is zeroized after adjudication completes (AC5/AD-12; RED-on-neuter)")
    void passwordZeroizedAfterAdjudication() throws Exception {
        HttpServer server = newServer(ex -> {
            drainBody(ex);
            sendJson(ex, 401, "{}");   // any outcome — the finally-block zeroize is what we assert
        });
        AsciiString raw = new AsciiString("s3cret");   // shared backing — Password does not copy (AC5 coverage)
        BindCredential credential = cred(raw);
        try (RopcSlice slice = slice(server)) {
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
    @DisplayName("saturation: a pool at capacity denies a 2nd bind DenyIndeterminate, no wire call, + zeroizes (AC6)")
    void saturation_deniesWithoutWork_andZeroizes() throws Exception {
        CountDownLatch requestReceived = new CountDownLatch(1);
        CountDownLatch holdPermit = new CountDownLatch(1);   // keeps verify#1 in-flight → the lone permit stays held
        AtomicInteger tokenHits = new AtomicInteger(0);      // F2 bite: a denied/saturated bind must NOT reach the IdP
        HttpServer server = newServer(ex -> {
            tokenHits.incrementAndGet();
            try {
                requestReceived.countDown();
                drainBody(ex);
                holdPermit.await();
                sendJson(ex, 401, "{}");   // released → verify#1 resolves DenyInvalid
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (IOException ioe) {
                // best-effort: a late write after holdPermit release may fail — not a verdict signal.
            }
        });

        AsciiString pw1 = new AsciiString("pw1");
        AsciiString pw2 = new AsciiString("pw2");
        try (RopcSlice slice = slice(server, 1)) {   // maxInflight = 1
            VerdictRequest first = verify(slice, cred(pw1));   // acquires the single permit, blocks at holdPermit
            assertTrue(requestReceived.await(5, TimeUnit.SECONDS), "verify#1 should reach the slow IdP (permit held)");

            // The assertions live in a try/finally so holdPermit is ALWAYS released — even if a RED-on-neuter
            // mutation makes second.future() time out (a stranded handler thread would otherwise hang the test JVM).
            try {
                long start = System.nanoTime();
                VerdictRequest second = verify(slice, cred(pw2));   // permit exhausted → fail-closed deny, NO wire call
                Verdict v2 = second.future().get(2, TimeUnit.SECONDS);
                long elapsedMs = (System.nanoTime() - start) / 1_000_000;

                assertThat(v2).as("a saturated pool denies a 2nd bind DenyIndeterminate (AD-11/AD-28(4))")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
                assertThat(elapsedMs).as("saturation must DENY without starting work (AC6)").isLessThan(1_000L);
                // F2 RED-on-neuter: the denied bind's token call must never reach the IdP. If sendAsync were fired
                // before admission.tryAcquire (the pre-fix shape), verify#2 would hit this handler → tokenHits == 2.
                assertThat(tokenHits.get())
                        .as("a saturated/denied bind must not transmit the ROPC request to the IdP (AC6 'without work')")
                        .isEqualTo(1);
                // Saturation-path zeroize runs on the caller thread before verify returns — race-free: pw2 is already
                // wiped the instant verify(slice, cred(pw2)) completed.
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
        RopcSlice.SliceConfig cfg = new RopcSlice.SliceConfig(any, "c", "s");
        // maxInflight=0: WITHOUT this guard, Semaphore(0) is valid and EVERY bind silently denies DenyIndeterminate
        // (fail-closed but broken/misconfigured) — the guard is the typed admission-capacity fail-fast.
        assertThatThrownBy(() -> new RopcSlice(HttpClient.newHttpClient(), cfg, 0))
                .isInstanceOf(IllegalArgumentException.class);
        // maxInflight<0 is independently caught by Semaphore's own constructor too, but the guard is the explicit
        // typed boundary; assert both document the intent.
        assertThatThrownBy(() -> new RopcSlice(HttpClient.newHttpClient(), cfg, -1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ── the amended contract's config guard: client_secret is MANDATORY (Story 3.4 T8; AC13) ─────────────────

    @Test
    @DisplayName("SliceConfig without a client_secret is rejected at construction (mandatory secret; RED-on-neuter)")
    void nullClientSecret_isRejectedAtConstruction() {
        // The 2.1 config allowed a null secret for the RFC 8705 mTLS path; that arm is gone (Story 3.4 T8,
        // 2026-08-29) and the secret is unconditionally required — drop the compact-ctor guard and a null secret
        // would NPE deep inside tokenRequest() instead (fail-open, password never zeroized).
        URI any = URI.create("http://127.0.0.1:1" + REALM + "/protocol/openid-connect/token");
        assertThatThrownBy(() -> new RopcSlice.SliceConfig(any, "c", null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clientSecret");
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
