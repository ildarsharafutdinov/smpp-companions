package smpp.companion.proxy.observability;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import ch.qos.logback.classic.Level;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.ProxyCompanionApplication;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.relay.BindInterceptor;
import smpp.companion.proxy.relay.ConnectionEntry;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.RelayIngressHandler;
import smpp.companion.proxy.relay.RelayStateManager;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.tls.SmppLegTlsFactory;

import io.netty.util.AsciiString;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 4.1 T6 (checkpoint 21) &mdash; the FR-OBS-2 proof: stdout is JSON-LINES. One JSON object per
 * line, {@code @timestamp} in ISO-8601 UTC, the startup line secret-free and field-complete, the bind
 * accept/reject lines carrying the contract fields, PDU bodies TRACE-gated (off by default) and the
 * bind password absent at ANY level.
 *
 * <p><b>The appender under test is the SHIPPED one, not a copy.</b> The tier's plain
 * {@code logback-test.xml} (which keeps {@code OutputCapture} assertions matching raw text) masks the
 * production shape for every other test &mdash; so this suite arms the REAL encoder three ways
 * (the shared {@link ObservabilityPairHarness} capture):
 * <ol>
 *   <li>a source pin on {@code logback-spring.xml} (encoder class, UTC, the ISO pattern, the INFO
 *       root &mdash; the {@code MetricsEndpointTest} source-pin idiom);</li>
 *   <li>a FULL boot under {@code --logging.config=classpath:logback-spring.xml} with stdout swapped
 *       into memory &mdash; Spring re-initializes logback from the production file, so EVERY boot line
 *       (framework noise included) must come out one-parseable-object-per-line;</li>
 *   <li>the harness's in-memory capture reusing the file-configured {@code LogstashEncoder} while the
 *       REAL fire sites are driven through the embedded-pair fixture &mdash; the accept at the ROK
 *       couple, the reject at the AD-33 deny plane, the TRACE bodies at {@code relayFramedPdu}.</li>
 * </ol>
 *
 * <p>RED-on-neuter: flip the encoder/timeZone/pattern in {@code logback-spring.xml}, add a secret to
 * the startup summary, drop the bind-family redaction, or emit a non-JSON stdout line from the boot
 * &mdash; each turns exactly one row below red.
 */
@Tag("integration")
@Tag("observability")
@Tag("p1")
@DisplayName("StructuredLog — FR-OBS-2: stdout is JSON-lines (UTC ISO stamps, secret-free, TRACE-gated)")
class StructuredLogTest extends ObservabilityPairHarness {

    @TempDir
    Path dir;

    private ConnectionRegistry registry;
    private RelayStateManager manager;

    // ---------- row 0: the shipped config pins the shape ------------------------------------

    @Test
    @DisplayName("logback-spring.xml pins the JSON-lines shape: LogstashEncoder, ISO_OFFSET_DATE_TIME, UTC, INFO root")
    void productionConfigPinsTheJsonLinesShape() throws IOException {
        String xml = readResource("/logback-spring.xml");
        assertThat(xml).as("the production console appender uses the logstash encoder")
                .contains("net.logstash.logback.encoder.LogstashEncoder");
        assertThat(xml).as("the timestamp pattern is the bracketed ISO constant (never a hand-rolled pattern)")
                .contains("[ISO_OFFSET_DATE_TIME]");
        assertThat(xml).as("the zone is pinned UTC (never the JVM default)")
                .contains("<timeZone>UTC</timeZone>");
        assertThat(xml).as("the shipped root level is INFO (TRACE bodies off by default)")
                .contains("<root level=\"INFO\">");
    }

    // ---------- row 1: a full boot under the production config emits pure JSON-lines stdout ----

    @Test
    @DisplayName("full boot under --logging.config: EVERY stdout line is one JSON object, UTC ISO stamps, "
            + "startup_summary present/secret-free, no bodies")
    void fullBootEmitsPureJsonLinesStdout() throws IOException {
        RelayTestFixtures.SmppTlsLegs tlsLegs = RelayTestFixtures.smppTlsLegs(dir);
        int bindPort = RelayTestFixtures.freePort();
        int metricsPort = RelayTestFixtures.freePort();
        // Stdout is swapped BEFORE the boot so even a start-time ConsoleAppender binding lands in the
        // sink — the boot's whole stdout window is captured, boot line noise included (a plain-text
        // line anywhere in it is exactly the FR-OBS-2 violation this row exists to catch).
        PrintStream originalOut = System.out;
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        System.setOut(new PrintStream(stdout, true, StandardCharsets.UTF_8));
        String raw;
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "companion.forward.mode-a.trust-store.path=" + tlsLegs.trustStore(),
                        "companion.forward.mode-a.trust-store.password=" + RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD,
                        "companion.forward.mode-a.routing[0].system-id=carrierOne",
                        "companion.forward.mode-a.routing[0].host=reverse.internal",
                        "companion.forward.mode-a.routing[0].port=2776")
                .run(
                        "--logging.config=classpath:logback-spring.xml", // beats the tier's logback-test.xml
                        "--companion.memory.max-inbound-depth=1",
                        "--companion.memory.concurrent-pairs=1",
                        "--companion.memory.safety-factor=1.0",
                        "--companion.bind.port=" + bindPort,
                        "--companion.metrics.port=" + metricsPort)) {
            assertThat(ctx.isActive()).as("the fixture boot must succeed (the MetricsEndpointTest builder pattern)")
                    .isTrue();
        } finally {
            System.setOut(originalOut);
        }
        raw = stdout.toString(StandardCharsets.UTF_8);

        List<String> lines = raw.lines().map(String::trim).filter(s -> !s.isEmpty()).toList();
        assertThat(lines).as("the booted app logged a non-empty stream").isNotEmpty();
        List<Map<String, Object>> parsed = parseEveryLine(lines);
        assertUtcIsoStamps(parsed);
        assertThat(parsed).allSatisfy(line -> {
            assertThat(line.get("level")).as("level field on every line").isNotNull();
            assertThat(line.get("message")).as("message field on every line").isNotNull();
        });
        assertThat(parsed)
                .as("framework logging itself rode the JSON encoder (the re-init actually applied — "
                        + "Spring's own 'Starting ...' / validator lines are JSON objects too)")
                .anySatisfy(line -> assertThat(String.valueOf(line.get("logger_name")))
                        .doesNotStartWith("smpp.companion.proxy"));

        // The startup/config-resolved line: field-complete (FR-OBS-2) and secret-free.
        Map<String, Object> startup = lineByEvent(parsed, "startup_summary");
        assertThat(startup.get("role")).isEqualTo("forward");
        assertThat(startup.get("mode")).isEqualTo("a");
        assertThat(startup.get("smpp_bind_host")).as("host present (the yml default)").isNotNull();
        assertThat(((Number) startup.get("smpp_bind_port")).intValue()).isEqualTo(bindPort);
        assertThat(((Number) startup.get("metrics_port")).intValue()).isEqualTo(metricsPort);
        assertThat(startup.get("routing_system_ids"))
                .as("the routing table is reflected (the bounded label universe)")
                .isEqualTo(List.of("carrierOne"));
        assertThat((List<Object>) startup.get("tls_protocols")).containsExactlyInAnyOrder("TLSv1.3", "TLSv1.2");
        assertThat(((Number) startup.get("max_inbound_depth")).intValue()).isOne();
        assertThat(startup.get("memory_budget_bytes")).as("the derived AD-30 budget is on the line").isNotNull();
        assertThat(startup.get("direct_memory_ceiling_bytes"))
                .as("the live ceiling the AD-30 self-check compared the budget against is on the line")
                .isNotNull();

        // Secret-free: neither the fixture's trust-store PASSWORD value nor any secret-named key
        // crossed — the summary draws only from non-secret config structure (a future field that
        // leaks either turns this red).
        assertThat(raw).doesNotContain(RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD);
        assertThat(parsed).allSatisfy(line -> assertThat(line.keySet())
                .as("no secret-named key on any line")
                .noneMatch(k -> k.toLowerCase(Locale.ROOT).contains("password")
                        || k.toLowerCase(Locale.ROOT).contains("secret")));

        // TRACE off by default: no PDU bodies anywhere in the boot's stream.
        assertThat(lines).as("no PDU bodies at default level").noneMatch(l -> l.contains("body=0x"));
    }

    // ---------- row 2: accept/reject lines from the REAL fire sites --------------------------

    @Test
    @DisplayName("bind accept/reject JSON lines carry the contract fields: system_id, verdict type, "
            + "AD-33 wire status (driven through the real fire sites)")
    void bindAcceptAndRejectLinesCarryTheContractFields() {
        armProductionJsonAppender();
        try {
            MeteredRelayObserver observer = new MeteredRelayObserver(
                    new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                    new RoutingTable(relayProperties()));

            rejectBind(observer); // BindInterceptor's deny plane — the worst-arm fire site
            couple(observer);     // the AD-25 ROK couple — the accept fire site

            List<Map<String, Object>> lines = capturedJsonLines();
            assertUtcIsoStamps(lines);

            Map<String, Object> reject = lineByEvent(lines, "bind_reject");
            assertThat(reject.get("system_id")).isEqualTo("legacy1");
            assertThat(reject.get("verdict")).isEqualTo("DenyInvalid");
            assertThat(reject.get("bind_resp_command_status"))
                    .as("the AD-33 collapse the relay synthesized for this very deny")
                    .isEqualTo("0x0000000D");

            Map<String, Object> accept = lineByEvent(lines, "bind_accept");
            assertThat(accept.get("system_id")).isEqualTo("legacy1");
            assertThat(accept.get("outcome")).isEqualTo("coupled");
        } finally {
            restoreTestLogging();
        }
    }

    // ---------- rows 3-4: TRACE gating + the password never ----------------------------------

    @Test
    @DisplayName("TRACE on the PDU logger: opaque bodies appear as parseable JSON lines (hex), the stray "
            + "re-bind is redacted — the password (plaintext AND hex) never crosses")
    void traceOnLogsBodiesAsJsonLinesButNeverThePassword() {
        armProductionJsonAppender();
        ch.qos.logback.classic.Logger pduLogger =
                (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(PDU_BODY_LOGGER);
        Level original = pduLogger.getLevel();
        pduLogger.setLevel(Level.TRACE);
        try {
            MeteredRelayObserver observer = new MeteredRelayObserver(
                    new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                    new RoutingTable(relayProperties()));
            couple(observer);
            ingress.writeInbound(inbound(opaquePdu(SUBMIT_SM, 301)));
            egress.writeInbound(inbound(opaquePdu(OPAQUE_DLR_TAG, 302)));
            // The residual password carrier: a stray post-couple re-bind relays as its ORIGINAL frame
            // — the one bind-family PDU that can reach the TRACE site.
            byte[] strayRebind = bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 303, "legacy1", "sekrit-pw");
            ingress.writeInbound(inbound(strayRebind));

            // Body lines must still be ONE object per line (a multi-line or raw-text body dump would
            // corrupt the JSON stream — this parse is the row's point, not an afterthought).
            List<Map<String, Object>> lines = capturedJsonLines();
            assertUtcIsoStamps(lines);
            assertThat(lines).anySatisfy(line -> assertThat(String.valueOf(line.get("message")))
                    .contains("relayed pdu: direction=" + Direction.INGRESS));
            assertThat(lines).anySatisfy(line -> assertThat(String.valueOf(line.get("message")))
                    .contains("relayed pdu: direction=" + Direction.EGRESS));
            String raw = sink.toString(StandardCharsets.UTF_8);
            assertThat(raw).as("the bind family's body is redacted — metadata only")
                    .contains("<redacted: bind family>");
            assertThat(raw)
                    .as("the bind password can never cross at ANY level (plaintext or hex)")
                    .doesNotContain("sekrit-pw")
                    .doesNotContain(hex(strayRebind));
        } finally {
            pduLogger.setLevel(original); // never leak TRACE into the other rows
            restoreTestLogging();
        }
    }

    @Test
    @DisplayName("TRACE off (the default): relayed traffic logs NO bodies — the JSON stream stays "
            + "alive (the accept line) but carries no content")
    void traceOffLogsNoBodies() {
        armProductionJsonAppender(); // the production config's own levels: root INFO, no TRACE anywhere
        try {
            MeteredRelayObserver observer = new MeteredRelayObserver(
                    new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                    new RoutingTable(relayProperties()));
            couple(observer);
            ingress.writeInbound(inbound(opaquePdu(SUBMIT_SM, 401)));

            String raw = sink.toString(StandardCharsets.UTF_8);
            assertThat(raw).as("the body logger is off by default — the relay is silent about content")
                    .doesNotContain("relayed pdu:")
                    .doesNotContain("body=0x");
            // The stream itself is alive (the accept line parsed) — only the bodies are gated.
            List<Map<String, Object>> lines = capturedJsonLines();
            lineByEvent(lines, "bind_accept");
        } finally {
            restoreTestLogging();
        }
    }

    // ---------- the embedded-pair fixture (the ThrowingObserverHardeningTest mirror) -----------

    private EmbeddedChannel ingress;
    private EmbeddedChannel egress;

    /**
     * Wires a COUPLED pair through the REAL production handlers: register + attach (the public
     * state-manager transitions), then the ROK {@code bind_resp} through the real
     * {@link RelayEgressInitializer} — the single production couple unit — so {@code onBindAccept}
     * fires exactly as in production and the accept JSON line is the REAL fire site's output.
     */
    private void couple(RelayObserver observer) {
        relayBeans();
        ingress = channel(new SmppFrameDecoder(), new SmppCodec(), new RelayIngressHandler(manager, observer));
        egress = channel(new RelayEgressInitializer(manager, observer));
        ConnectionEntry entry = manager.register(ingress, new SystemId(new AsciiString("legacy1")));
        manager.attachEgress(ingress.id(), egress);
        egress.writeInbound(inbound(
                bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));
        assertThat(entry.coupled())
                .as("precondition: the ROK drove the REAL couple unit — the accept fire site ran")
                .isTrue();
        drainInbound(egress); // the decoded ROK (no EgressLeg from this package — the T4 suite's note)
        drainInbound(ingress);
    }

    /** Drives a bind through the REAL deny plane: BindInterceptor + an already-settled DenyInvalid. */
    private void rejectBind(RelayObserver observer) {
        relayBeans();
        ProxyCompanionProperties properties = relayProperties();
        ingress = channel(
                new SmppFrameDecoder(), new SmppCodec(),
                new BindInterceptor(denyingVerifier(), manager, observer, properties,
                        new RelayEgressInitializer(manager, observer),
                        new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                        new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run)),
                new RelayIngressHandler(manager, observer));
        ingress.writeInbound(inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 42, "legacy1", "pw123456")));
        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("precondition: the deny synthesis ran — the reject fire site fired").isNotNull();
        deny.release(); // readOutbound hands the reader ownership (the T7 trap)
    }

    private void relayBeans() {
        registry = new ConnectionRegistry();
        manager = new RelayStateManager(registry);
    }

    private static ProxyCompanionProperties relayProperties() {
        return RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1);
    }

    private static String readResource(String resource) throws IOException {
        try (java.io.InputStream in = StructuredLogTest.class.getResourceAsStream(resource)) {
            assertThat(in).as("classpath resource %s", resource).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
