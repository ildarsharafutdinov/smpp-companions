package smpp.companion.proxy.observability;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ConfigurableApplicationContext;

import io.micrometer.core.instrument.Counter;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

import smpp.companion.proxy.ProxyCompanionApplication;
import smpp.companion.proxy.bootstrap.ProxyCompanionLifecycle;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Story 4.1 T2 (checkpoint 18): the hardened endpoint contract — I/O matrix rows 1-4 plus the
 * shutdown row and the by-construction pins (literal loopback bind, dedicated loop). Full-app boots
 * drive the REAL component-scan wiring (forward.mode-a, the {@code BootstrapLifecycleTest} builder
 * pattern — no slice runner), so the bean's presence in the scanned context is proven, not assumed.
 *
 * <p><b>Raw-socket client on purpose:</b> the handler answers every request with {@code
 * Connection: close} + a close listener, so a byte-level write-then-read-until-EOF exchange is
 * deterministic AND doubles as the connection-closed assertion (the EOF IS the close). A
 * {@code java.net.http.HttpClient} would mask both the close and the malformed-request rows (it
 * cannot send an oversized header or a lying Content-Length). The metrics port is passed as a
 * run-arg — HIGHEST precedence, beating application.yml's shipped 9090 ({@code .properties()}
 * cannot, the T5b lesson), so these boots never collide with a locally-running Prometheus.
 */
@Tag("integration")
@Tag("deploy")
@Tag("p2")
class MetricsEndpointTest {

    @Test
    @DisplayName("row 1: GET /metrics -> 200 Prometheus text; a second scrape is byte-identical (read-only)")
    void scrapeServesReadonlyPrometheusText(@TempDir Path dir) throws IOException {
        int port = RelayTestFixtures.freePort();
        try (ConfigurableApplicationContext ctx = bootForwardA(dir, port)) {
            assertThat(ctx.getBean(MetricsEndpointLifecycle.class).isRunning()).isTrue();
            // Step-04 review (finding #1): the @Primary displacement is observed in a BOOTED context —
            // removing @Component from MeteredRelayObserver would silently hand the relay back to the
            // noop while every direct-construction test stayed green. This row pins both halves: the
            // booted context serves the PRODUCTION observer behind the seam, and its pre-registered
            // close-grid series (zero-valued) is already on the scrape surface.
            assertThat(ctx.getBean(RelayObserver.class))
                    .as("@Primary displacement: the booted context serves the production observer")
                    .isInstanceOf(MeteredRelayObserver.class);
            // One known meter so the scrape has deterministic content (a bare registry scrapes empty).
            Counter.builder("story41.endpoint.probe").description("T2 scrape-contract probe")
                    .register(ctx.getBean(PrometheusMeterRegistry.class)).increment(3.0);

            String first = exchange(port, get(MetricsHttpHandler.SCRAPE_PATH));
            assertThat(first).as("row 1: 200").startsWith("HTTP/1.1 200");
            assertThat(first.toLowerCase(Locale.ROOT))
                    .as("row 1: Prometheus text format")
                    .contains("content-type: text/plain")
                    .contains("# help")
                    .contains("# type")
                    .contains("story41_endpoint_probe_total 3.0")
                    // the production observer's pre-registered close grid rides the same scrape
                    .contains("relay_connections_closed_total");
            assertThat(exchange(port, get(MetricsHttpHandler.SCRAPE_PATH)))
                    .as("row 1: idempotent — a scrape mutates nothing (not even a scrape counter)")
                    .isEqualTo(first);
        }
    }

    @Test
    @DisplayName("row 2: POST/PUT/DELETE /metrics -> 405 with Allow: GET")
    void nonGetRequestsAre405(@TempDir Path dir) throws IOException {
        int port = RelayTestFixtures.freePort();
        try (ConfigurableApplicationContext ctx = bootForwardA(dir, port)) {
            for (String method : new String[] {"POST", "PUT", "DELETE"}) {
                String resp = exchange(port, method(method, MetricsHttpHandler.SCRAPE_PATH));
                assertThat(resp).as(method + " must be 405").startsWith("HTTP/1.1 405");
                assertThat(resp.toLowerCase(Locale.ROOT)).as(method + " must advertise Allow: GET").contains("allow: get");
            }
        }
    }

    @Test
    @DisplayName("row 3: GET on any non-exact path -> 404 (query string included — exactness is fail-closed)")
    void nonExactPathsAre404(@TempDir Path dir) throws IOException {
        int port = RelayTestFixtures.freePort();
        try (ConfigurableApplicationContext ctx = bootForwardA(dir, port)) {
            for (String path : new String[] {"/metrics/foo", "/", "/metrics/", "/metrics?x=1"}) {
                assertThat(exchange(port, get(path))).as("GET " + path + " must be 404").startsWith("HTTP/1.1 404");
            }
        }
    }

    @Test
    @DisplayName("row 4: oversized header / oversized body -> 413, connection closed, no trace on the wire")
    void oversizedRequestsAre413AndClosed(@TempDir Path dir) throws IOException {
        int port = RelayTestFixtures.freePort();
        try (ConfigurableApplicationContext ctx = bootForwardA(dir, port)) {
            // Header block beyond MetricsHttpHandler.MAX_HEADER_SIZE (8 KiB): Netty 4.x does NOT
            // fireExceptionCaught — the codec delivers the malformed request with a FAILED DecoderResult
            // and MetricsHttpHandler must refuse it (the regression this row pins: serving it would be a
            // 200). NUL-free 'a' padding keeps the exchange helper's US-ASCII write honest.
            String bigHeader = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Big: " + "a".repeat(16 * 1024) + "\r\n\r\n";
            String resp = exchange(port, bigHeader);
            assertThat(resp).as("oversized header must be 413").startsWith("HTTP/1.1 413");
            assertThat(resp).as("no stack trace on the wire — static one-line body").doesNotContain("Exception");

            // Body beyond MAX_CONTENT_LENGTH, fully SENT in one write: HttpObjectAggregator answers
            // 413 ITSELF (handleOversizedMessage writes through the codec encoder) — the request
            // never reaches this pipeline's handler. Netty 4.2.16 closes after that 413 only when
            // the request is NOT keep-alive (!100-continue && !keepAlive, verbatim in its source),
            // so this raw request MUST carry Connection: close like every helper-built one — else
            // the channel stays open for a next request and the read-until-EOF below blocks until
            // the socket timeout with the 413 already received (the original RED). (A declared-
            // but-unsent length would merely stall the channel waiting for bytes — not a bounded
            // rejection.)
            String bigBody = "POST /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 16384\r\n"
                    + "Connection: close\r\n\r\n" + "\0".repeat(16 * 1024);
            assertThat(exchange(port, bigBody)).as("oversized body must be 413").startsWith("HTTP/1.1 413");
        }
    }

    @Test
    @DisplayName("shutdown row: close -> port released (later scrape refused), dedicated companion-metrics loop gone")
    void stopReleasesPortAndQuiescesTheDedicatedLoop(@TempDir Path dir) throws IOException {
        int port = RelayTestFixtures.freePort();
        ConfigurableApplicationContext ctx = bootForwardA(dir, port);
        MetricsEndpointLifecycle lifecycle = ctx.getBean(MetricsEndpointLifecycle.class);
        try {
            assertThat(lifecycle.isRunning()).isTrue();
            // Dedicated-loop isolation (AD-19/AD-28): BOTH planes are live on DISTINCT named loops —
            // the scrape surface never rides (or blocks on) the shared companion-relay data plane.
            Set<String> live = threadNames();
            assertThat(live).as("the dedicated companion-metrics loop must be running").anyMatch(n -> n.startsWith("companion-metrics"));
            assertThat(live).as("the shared relay loop is live too — and separate").anyMatch(n -> n.startsWith("companion-relay"));
        } finally {
            ctx.close();
        }
        assertThat(lifecycle.isRunning()).as("context close must run stop()").isFalse();
        assertThat(threadNames()).as("the dedicated loop's thread is gone (awaited shutdownGracefully)")
                .noneMatch(n -> n.startsWith("companion-metrics"));
        // The port is released: the Socket ctor THROWS (ConnectException) if anything still listens —
        // the ctor is the assertion (the RelayServerLifecycleTest reclaimed-port idiom).
        assertThatThrownBy(() -> exchange(port, get(MetricsHttpHandler.SCRAPE_PATH)))
                .as("a later scrape must be refused after stop")
                .isInstanceOf(IOException.class);
    }

    @Test
    @DisplayName("absent companion.metrics node -> the endpoint stays down (not-running, nothing bound)")
    void absentMetricsNodeLeavesTheEndpointDown() {
        // modeBProperties constructs WITHOUT the metrics node (metrics == null) — the programmatic
        // fixture path; the lifecycle's not-running tripwire keeps it endpoint-free.
        new ApplicationContextRunner()
                .withBean(ProxyCompanionProperties.class,
                        () -> RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1))
                .withBean(PrometheusMeterRegistry.class,
                        () -> new PrometheusMeterRegistry(PrometheusConfig.DEFAULT))
                .withUserConfiguration(MetricsEndpointLifecycle.class)
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(MetricsEndpointLifecycle.class);
                    assertThat(ctx.getBean(MetricsEndpointLifecycle.class).isRunning())
                            .as("no companion.metrics node -> not-running")
                            .isFalse();
                });
    }

    @Test
    @DisplayName("occupied metrics port: the boot FAILS (AD-17 fail-fast through start()) and the "
            + "catch-path loop quiesce leaves no companion-metrics thread")
    void occupiedMetricsPortFailsStartupAndQuiescesTheLoop(@TempDir Path dir) throws IOException {
        // Step-04 review (finding #2) — mirrors RelayServerLifecycleTest's occupied-port row for the
        // full-app boot: an occupied port must refuse the refresh (never a silently-down endpoint),
        // and the lifecycle's catch block must have quiesced the freshly created dedicated loop —
        // a failed boot may not strand a companion-metrics thread. The quiesce is AWAITED in
        // start()'s catch, so this is race-free: the thread is gone before run() even throws.
        // (This row caught a real bug: Netty's sync() sneaky-throws the raw checked BindException,
        // which the original RuntimeException-only catch sailed past — the loop leaked.)
        try (ServerSocket occupied = new ServerSocket(RelayTestFixtures.freePort())) {
            Throwable thrown = catchThrowable(() -> bootForwardA(dir, occupied.getLocalPort()));
            assertThat(thrown)
                    .as("an occupied metrics port must fail the context refresh (AD-17 fail-fast)")
                    .isNotNull();
            assertThat(threadNames())
                    .as("the failed start's catch path quiesced the dedicated loop (no thread leak)")
                    .noneMatch(n -> n.startsWith("companion-metrics"));
        }
    }

    @Test
    @DisplayName("phase pin: METRICS_ENDPOINT_PHASE sits strictly between the acceptor (stops first) "
            + "and the app lifecycle (stops last)")
    void metricsPhaseSitsStrictlyBetweenAcceptorAndApp() {
        // Step-04 review (finding #4) — mirrors RelayServerLifecycleTest's phase pin: exact constants,
        // not just "running" (a neutered getPhase falls back to the implicit default and goes RED
        // here), plus the load-bearing ORDER: scrapes stay live LATE — after the data plane has
        // closed, before the app window (the future AD-22 drain).
        assertThat(new MetricsEndpointLifecycle(RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1),
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT)).getPhase())
                .isEqualTo(MetricsEndpointLifecycle.METRICS_ENDPOINT_PHASE);
        assertThat(MetricsEndpointLifecycle.METRICS_ENDPOINT_PHASE)
                .as("the metrics endpoint stops after the app lifecycle, before the acceptor")
                .isGreaterThan(ProxyCompanionLifecycle.APP_PHASE)
                .isLessThan(RelayServerLifecycle.RELAY_ACCEPTOR_PHASE);
    }

    @Test
    @DisplayName("by construction: the bind host is the LITERAL 127.0.0.1, the loop is companion-metrics, "
            + "and application.yml ships the metrics port default (source-pinned)")
    void theBindAddressIsTheLiteralLoopbackInSource() throws IOException {
        // The CWD of :proxy:test is the proxy module dir (the Relay026ConstantContractTest scan idiom;
        // `clean build` covers the incremental-UP-TO-DATE trap for source scans).
        Path src = Path.of("src/main/java/smpp/companion/proxy/observability/MetricsEndpointLifecycle.java");
        assertThat(Files.exists(src)).as("lifecycle source present (test CWD = proxy module)").isTrue();
        String code = Files.readString(src);
        assertThat(code).as("the loopback literal is a named constant").contains("LOOPBACK_BIND_HOST = \"127.0.0.1\"");
        assertThat(code).as("the acceptor binds the literal, nothing else").contains("bootstrap.bind(LOOPBACK_BIND_HOST");
        assertThat(code).as("the dedicated loop is named in code").contains("new DefaultThreadFactory(\"companion-metrics\")");
        assertThat(code).as("no host key can exist — the bind host is only ever the literal")
                .doesNotContain(".metrics().host");
        // Step-04 review (finding #3): the shipped default is part of the by-construction posture —
        // deleting the yml node would ship an unobservable proxy with a green build (an absent node
        // legitimately leaves the endpoint down for programmatic fixtures, so only this pin notices).
        Path yml = Path.of("src/main/resources/application.yml");
        assertThat(Files.exists(yml)).as("application.yml present (test CWD = proxy module)").isTrue();
        assertThat(Files.readString(yml))
                .as("application.yml ships the companion.metrics.port default — production boots observable")
                .contains("metrics:")
                .contains("port: 9090");
    }

    // --- fixtures ---------------------------------------------------------------------------

    /**
     * A forward.mode-a full-app boot (the {@code BootstrapLifecycleTest} builder pattern): branch
     * keys as default properties (yml carries none of them), the yml-overriding keys as run-args —
     * minimal AD-30 budget, a free relay bind port, and the metrics endpoint on {@code metricsPort}
     * (run-args beat application.yml's shipped 9090; {@code .properties()} does not).
     */
    private static ConfigurableApplicationContext bootForwardA(Path dir, int metricsPort) throws IOException {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        return new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "companion.forward.mode-a.trust-store.path=" + legs.trustStore(),
                        "companion.forward.mode-a.trust-store.password=" + RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD,
                        "companion.forward.mode-a.routing[0].system-id=carrierOne",
                        "companion.forward.mode-a.routing[0].host=reverse.internal",
                        "companion.forward.mode-a.routing[0].port=2776")
                .run(
                        "--companion.memory.max-inbound-depth=1",
                        "--companion.memory.concurrent-pairs=1",
                        "--companion.memory.safety-factor=1.0",
                        "--companion.bind.port=" + RelayTestFixtures.freePort(),
                        "--companion.metrics.port=" + metricsPort);
    }

    private static String get(String path) {
        return method("GET", path);
    }

    private static String method(String method, String path) {
        return method + " " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    }

    /**
     * Writes the raw request, reads the response until EOF (every endpoint response closes the
     * connection, so EOF is deterministic — and IS the connection-closed assertion). The Socket ctor
     * throws {@code ConnectException} when nothing listens, which is exactly the stopped-endpoint
     * probe in the shutdown test.
     */
    private static String exchange(int port, String rawRequest) throws IOException {
        // getLoopbackAddress() = the server's literal 127.0.0.1 (Error Prone AddressSelection; the
        // RelayServerLifecycleTest probe idiom).
        try (Socket socket = new Socket(java.net.InetAddress.getLoopbackAddress(), port)) {
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(rawRequest.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = socket.getInputStream().read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    private static Set<String> threadNames() {
        return Thread.getAllStackTraces().keySet().stream()
                .map(Thread::getName)
                .collect(Collectors.toSet());
    }
}
