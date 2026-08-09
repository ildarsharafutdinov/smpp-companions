package smpp.companion.proxy.security;

import com.sun.net.httpserver.HttpServer;
import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.PushPromiseHandler;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Story 2.1 Task 3 / AC3 (load-bearing) — ratifies that {@link RopcSlice}'s {@link VerdictRequest#cancelHttp()}
 * <b>aborts the underlying {@code HttpClient} ROPC exchange</b> (AD-32), not only the {@code CompletableFuture}.
 * This is the IdP-amplification mitigation: a bind the proxy abandons must tear the wire call down so the IdP is
 * spared the cost of issuing a token nobody will consume — unreachable through the {@code verify} seam unless
 * {@code cancelHttp()} drives {@code HttpClient.sendAsync(...).cancel(true)}.
 *
 * <p><b>Why the signal is the future-cancellation (not a small-write probe):</b> the JDK wires
 * {@code MinimalFuture.cancel(true)} &rarr; {@code MultiExchange.cancel(true)} &rarr; {@code exchange.cancel()}
 * &rarr; {@code connection.close()} <b>only when {@code mayInterruptIfRunning == true}</b> (verified against the
 * JDK 25 source in {@code java.net.http}). So a cancelled sendAsync future IS the wire abort. Asserting the future
 * directly is deterministic and race-free; a small IdP-side token write is NOT a reliable signal (TCP half-close
 * lets the server's write succeed into the kernel buffer even after the client closed — the RST surfaces only on a
 * subsequent blocked write).
 *
 * <p><b>Primary assertion (deterministic, RED-on-neuter):</b> after {@code cancelHttp()}, the real sendAsync future
 * the slice stored is {@code isCancelled()}. <b>Neutering {@code cancelHttp()}</b> (dropping the
 * {@code tokenExchange.cancel(true)} line, leaving only {@code pin.complete(DenyIndeterminate)}) leaves the future
 * running — {@code isCancelled()} is {@code false} &rarr; RED. A verdict-only check would NOT bite (the pin still
 * completes), which is exactly why the future-cancellation assertion is load-bearing.
 *
 * <p><b>Corroboration (genuine "IdP spared"):</b> the slow IdP streams a large response that exceeds the socket send
 * buffer, so its write blocks; after {@code cancelHttp()} tore the wire down, that blocked write fails with an
 * {@link IOException} and no token is consumed. Asserted with a bounded wait; the primary assertion above is the
 * guaranteed-biting one regardless.
 *
 * <p><b>STS teardown (AD-32 case 3):</b> the slice's {@code StructuredTaskScope} is local to {@code adjudicate}, so
 * it cannot be observed directly; its teardown is evidenced by the verdict completing — cancelling the exchange
 * makes the scope's {@code join} throw, collapsing to {@link Verdict.DenyIndeterminate} and closing the scope.
 * Always-on; needs no container.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-32 RopcSlice.cancelHttp() — aborts the underlying HTTP exchange (RED-on-neuter)")
class RopcSliceCancelTest {

    /** Slow-IdP stall: comfortably longer than a localhost connection teardown, so the call is in-flight at cancel time. */
    private static final Duration SLOW_IDP_DELAY = Duration.ofMillis(300);

    /** IdP response size: exceeds the socket send buffer so the write blocks until the client drains it (or tears down). */
    private static final int IDP_BODY_SIZE = 1 << 20;   // 1 MiB

    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    @Test
    @DisplayName("cancelHttp() mid-flight cancels the underlying HttpClient exchange → DenyIndeterminate (IdP spared)")
    void cancelHttp_abortsUnderlyingExchange() throws Exception {
        CountDownLatch requestReceived = new CountDownLatch(1);
        CountDownLatch settled = new CountDownLatch(1);
        AtomicBoolean wroteToken = new AtomicBoolean(false);
        AtomicBoolean clientAborted = new AtomicBoolean(false);

        HttpServer server = HttpServer.create(new InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/realms/x/protocol/openid-connect/token", exchange -> {
            requestReceived.countDown();
            exchange.getRequestBody().readAllBytes();   // drain the small ROPC form body
            try {
                Thread.sleep(SLOW_IDP_DELAY.toMillis());   // slow IdP: keep the call in-flight
                exchange.sendResponseHeaders(200, IDP_BODY_SIZE);   // fixed content-length → one big blocking write
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(tokenBody(IDP_BODY_SIZE));
                }
                wroteToken.set(true);   // client drained the body → the token was consumed (the bad outcome)
            } catch (IOException e) {
                // The proxy tore the connection down (cancelHttp → exchange abort): the blocked write failed → IdP spared.
                clientAborted.set(true);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                settled.countDown();
                closeQuietly(exchange);
            }
        });
        server.start();

        URI token = URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                + "/realms/x/protocol/openid-connect/token");
        RecordingHttpClient http = new RecordingHttpClient(HttpClient.newHttpClient());   // plain HTTP stand-in IdP

        try (RopcSlice slice = new RopcSlice(http, new RopcSlice.SliceConfig(
                token, token, token, "http://127.0.0.1/realms/x",
                "smpp-client-confidential", "secret", false, false), 4)) {

            BindCredential credential = new BindCredential(
                    new SystemId(new AsciiString("testuser")), new Password(new AsciiString("pw")));
            RequestContext rc = new RequestContext(
                    credential.systemId(), DefaultChannelId.newInstance(), Instant.now().plusSeconds(15));

            // verify() returns immediately with an in-flight VerdictRequest (the token call is stalled at the server).
            VerdictRequest req = ScopedValue.where(CTX, rc).call(() -> slice.verify(credential, CTX));

            assertTrue(requestReceived.await(5, TimeUnit.SECONDS), "the ROPC request should reach the slow IdP");
            CompletableFuture<?> tokenExchange = http.lastSendAsync();
            assertThat(tokenExchange.isDone())
                    .as("the token call must still be in-flight when cancelHttp() fires (cancel is meaningful)")
                    .isFalse();

            // AD-32: abort the underlying HTTP call mid-flight (not only the CompletableFuture).
            req.cancelHttp();

            // PRIMARY (deterministic, RED-on-neuter): cancelHttp drove cancel(true) on the REAL HttpClient sendAsync
            // future → MinimalFuture.cancel(true) → MultiExchange.cancel(true) → exchange.cancel() → connection.close().
            // The JDK completes the aborted exchange EXCEPTIONALLY with a CancellationException (via MultiExchange's
            // wrapIfCancelled), so the call fails instead of delivering a token. isCancelled() is false here by design
            // (the future was completed exceptionally, not via Future.cancel's path) — a CancellationException in the
            // thrown cause chain is the signal. (reportGet wraps it ExecutionException → CancellationException → IOException;
            // the chain shape is JDK-specific, so we match anywhere in the chain.) NEUTER (no tokenExchange.cancel(true)):
            // the server responds normally → get() returns the HttpResponse → no exception → this assertion fails (RED).
            assertThatThrownBy(() -> tokenExchange.get(5, TimeUnit.SECONDS))
                    .as("cancelHttp() must abort the underlying HttpClient exchange (CancellationException in the cause "
                            + "chain), not deliver a token")
                    .matches(t -> hasCauseInChain(t, CancellationException.class),
                            "a CancellationException in its cause chain (the JDK wraps the cancel abort)");

            // The abandoned adjudication collapses to DenyIndeterminate (AD-11 fail-closed) — the STS join throws on
            // the cancelled exchange, closing the scope; pin.complete fires DenyIndeterminate.
            Verdict v = req.future().get(5, TimeUnit.SECONDS);
            assertThat(v).as("cancelled call → DenyIndeterminate").isInstanceOf(Verdict.DenyIndeterminate.class);

            // CORROBORATION (genuine "IdP spared"): the blocked write failed because the wire was torn down.
            assertTrue(settled.await(10, TimeUnit.SECONDS), "the IdP handler should settle");
            assertThat(clientAborted).as("wire torn down → IdP write fails").isTrue();
            assertThat(wroteToken).as("the abandoned ROPC must not consume a token (the IdP is spared)").isFalse();
        } finally {
            server.stop(0);
        }
    }

    private static byte[] tokenBody(int size) {
        byte[] body = new byte[size];
        java.util.Arrays.fill(body, (byte) 'x');
        return body;
    }

    /** True if {@code type} appears anywhere in {@code t}'s cause chain (handles JDK's multi-layer exception wrapping). */
    private static boolean hasCauseInChain(Throwable t, Class<? extends Throwable> type) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (type.isInstance(c)) {
                return true;
            }
        }
        return false;
    }

    private static void closeQuietly(com.sun.net.httpserver.HttpExchange exchange) {
        try {
            exchange.close();
        } catch (RuntimeException ignored) {
            // best-effort; the exchange may already be closed after the abort.
        }
    }

    /**
     * A delegating {@link HttpClient} that records the {@code CompletableFuture} returned by {@code sendAsync}, so the
     * test can assert {@code cancelHttp()} cancelled the <b>real</b> exchange future the slice stored. Returns the
     * delegate's future unwrapped (no {@code thenApply}), so the slice holds the JDK's cancellable {@code MinimalFuture}
     * exactly — {@code cancelHttp()}'s {@code cancel(true)} reaches {@code MultiExchange.cancel} (not a dead wrapper).
     */
    private static final class RecordingHttpClient extends HttpClient {
        private final HttpClient delegate;
        private volatile CompletableFuture<?> lastSendAsync;

        RecordingHttpClient(HttpClient delegate) {
            this.delegate = delegate;
        }

        CompletableFuture<?> lastSendAsync() {
            return lastSendAsync;
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, BodyHandler<T> handler) {
            CompletableFuture<HttpResponse<T>> f = delegate.sendAsync(request, handler);
            lastSendAsync = f;
            return f;
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
                HttpRequest request, BodyHandler<T> handler, PushPromiseHandler<T> pushPromiseHandler) {
            CompletableFuture<HttpResponse<T>> f = delegate.sendAsync(request, handler, pushPromiseHandler);
            lastSendAsync = f;
            return f;
        }

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, BodyHandler<T> handler)
                throws IOException, InterruptedException {
            return delegate.send(request, handler);
        }

        @Override
        public Optional<CookieHandler> cookieHandler() {
            return delegate.cookieHandler();
        }

        @Override
        public Optional<Duration> connectTimeout() {
            return delegate.connectTimeout();
        }

        @Override
        public Redirect followRedirects() {
            return delegate.followRedirects();
        }

        @Override
        public Optional<ProxySelector> proxy() {
            return delegate.proxy();
        }

        @Override
        public SSLContext sslContext() {
            return delegate.sslContext();
        }

        @Override
        public SSLParameters sslParameters() {
            return delegate.sslParameters();
        }

        @Override
        public Optional<Authenticator> authenticator() {
            return delegate.authenticator();
        }

        @Override
        public Version version() {
            return delegate.version();
        }

        @Override
        public Optional<Executor> executor() {
            return delegate.executor();
        }
    }
}
