package smpp.companion.proxy.observability;

import java.nio.charset.StandardCharsets;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;

/**
 * Story 4.1 (FR-OBS-1): the hardened read-only Prometheus endpoint contract (I/O matrix rows 1-4).
 * Per-channel instance (created by {@link MetricsEndpointLifecycle}'s initializer &mdash; the relay
 * pipelines' per-channel discipline; it is stateless but never shared). The contract:
 *
 * <ul>
 *   <li>GET with the uri EXACTLY {@code /metrics} (a query string is not the exact path) &rarr;
 *       200, {@link PrometheusMeterRegistry#scrape()} body, {@code text/plain; version=0.0.4}.
 *       Read-only: a scrape reads the registry and mutates NOTHING &mdash; not even a scrape
 *       counter (idempotence is matrix row 1's assertion).</li>
 *   <li>Any other method &rarr; 405 with {@code Allow: GET} (row 2).</li>
 *   <li>Any other path &rarr; 404 (row 3).</li>
 *   <li>Malformed/oversized requests &rarr; 4xx, connection closed, and NEVER a stack trace on the
 *       wire (row 4). Two distinct mechanisms (both proven empirically on Netty 4.2.16): an oversized
 *       HEADER BLOCK arrives here as a request with a FAILED {@code DecoderResult} ({@code
 *       TooLongHttpHeaderException} &sub; {@code TooLongFrameException}) &mdash; refused below; an
 *       oversized BODY is answered 413 BY THE AGGREGATOR ITSELF ({@code
 *       HttpObjectAggregator.handleOversizedMessage} writes the response through the codec) &mdash;
 *       it never reaches this handler. {@link #exceptionCaught} remains defense-in-depth for any
 *       other pipeline error, answering with a static one-line body.</li>
 * </ul>
 *
 * <p><b>Bounded by construction:</b> the request-shape limits below are the ones {@link
 * MetricsEndpointLifecycle} mounts the pipeline with ({@code HttpServerCodec} line/header caps +
 * {@code HttpObjectAggregator} content cap) &mdash; they live HERE so the endpoint's contract and
 * its pipeline share one owner. A scrape request is tiny; single-digit-KiB caps cannot reject a
 * legitimate Prometheus probe.
 *
 * <p><b>One scrape per connection:</b> every response carries {@code Connection: close} and the
 * write listener closes the channel &mdash; the endpoint is one-shot telemetry, never a keep-alive
 * session pool. Rejected requests log ONE debug line each (bounded, debug-gated &mdash; a probe
 * flood must not spam the JSON log stream, matrix row 2's "bounded WARN at debug level").
 */
@Slf4j
@RequiredArgsConstructor
final class MetricsHttpHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    /** The exact (and only) scrape path — query strings do not match (fail-closed exactness). */
    static final String SCRAPE_PATH = "/metrics";

    /** Request-line cap for the codec (bytes). */
    static final int MAX_INITIAL_LINE_LENGTH = 1024;

    /** Total header-block cap for the codec (bytes). */
    static final int MAX_HEADER_SIZE = 8 * 1024;

    /** Aggregated content cap ({@code HttpObjectAggregator}) and the codec's chunk cap (bytes). */
    static final int MAX_CONTENT_LENGTH = 8 * 1024;

    /** The Prometheus text-format content type (the registry's own scrape type). */
    private static final String PROMETHEUS_TEXT = "text/plain; version=0.0.4; charset=utf-8";

    private static final String PLAIN_TEXT = "text/plain; charset=utf-8";

    private final PrometheusMeterRegistry registry;

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        // Netty 4.x does NOT fireExceptionCaught for HTTP decode failures: the codec delivers the
        // (partial) request downstream carrying a FAILED DecoderResult — e.g. TooLongHttpHeaderException
        // for a header block beyond MAX_HEADER_SIZE (proven empirically on 4.2.16: the malformed request
        // reaches this handler and would otherwise be SERVED). Refuse it explicitly.
        if (request.decoderResult().isFailure()) {
            Throwable cause = request.decoderResult().cause();
            log.debug("metrics endpoint: rejected a malformed request ({})", cause);
            writeAndClose(ctx, response(
                    cause instanceof TooLongFrameException ? HttpResponseStatus.REQUEST_ENTITY_TOO_LARGE
                                                           : HttpResponseStatus.BAD_REQUEST,
                    PLAIN_TEXT, "request rejected\n"));
            return;
        }
        if (request.method() != HttpMethod.GET) {
            log.debug("metrics endpoint: rejected {} {} — GET /metrics is the only supported request",
                    request.method(), request.uri()); // bounded: one debug line, no stack trace anywhere
            FullHttpResponse resp = response(HttpResponseStatus.METHOD_NOT_ALLOWED, PLAIN_TEXT,
                    "method not allowed (GET only)\n");
            resp.headers().set(HttpHeaderNames.ALLOW, HttpMethod.GET.name());
            writeAndClose(ctx, resp);
            return;
        }
        if (!SCRAPE_PATH.equals(request.uri())) {
            log.debug("metrics endpoint: rejected GET {} — the exact path is /metrics", request.uri());
            writeAndClose(ctx, response(HttpResponseStatus.NOT_FOUND, PLAIN_TEXT, "not found (exact path: /metrics)\n"));
            return;
        }
        writeAndClose(ctx, response(HttpResponseStatus.OK, PROMETHEUS_TEXT, registry.scrape()));
    }

    /**
     * Defense-in-depth for pipeline errors outside the two documented row-4 paths (oversized headers
     * surface as failed-DecoderResult requests in {@link #channelRead0}; oversized bodies are
     * answered 413 by the aggregator itself): answers a 4xx with a static one-line body, then the
     * connection closes. Best-effort by necessity (the codec may already be mid-failure); this method
     * never throws &mdash; a handler error here would only race the close it is trying to perform.
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.debug("metrics endpoint: rejected a malformed request ({})", cause.toString());
        if (!ctx.channel().isActive()) {
            ctx.close();
            return;
        }
        HttpResponseStatus status =
                cause instanceof TooLongFrameException ? HttpResponseStatus.REQUEST_ENTITY_TOO_LARGE
                                                        : HttpResponseStatus.BAD_REQUEST;
        try {
            writeAndClose(ctx, response(status, PLAIN_TEXT, "request rejected\n"));
        } catch (RuntimeException e) {
            ctx.close(); // never propagate out of the error path
        }
    }

    private static FullHttpResponse response(HttpResponseStatus status, String contentType, String body) {
        ByteBuf content = Unpooled.copiedBuffer(body, StandardCharsets.UTF_8);
        FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, content);
        resp.headers().set(HttpHeaderNames.CONTENT_TYPE, contentType);
        HttpUtil.setContentLength(resp, content.readableBytes());
        HttpUtil.setKeepAlive(resp, false); // Connection: close — one scrape per connection
        return resp;
    }

    private static void writeAndClose(ChannelHandlerContext ctx, FullHttpResponse resp) {
        ctx.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
    }
}
