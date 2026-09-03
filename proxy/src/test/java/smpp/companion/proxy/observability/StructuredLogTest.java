package smpp.companion.proxy.observability;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.text.ParseException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.util.JSONObjectUtils;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.OutputStreamAppender;
import ch.qos.logback.core.joran.spi.JoranException;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.DefaultChannelId;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;

import smpp.companion.codec.bind.SmppBindPdu;
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
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.tls.SmppLegTlsFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Story 4.1 T6 (checkpoint 21) &mdash; the FR-OBS-2 proof: stdout is JSON-LINES. One JSON object per
 * line, {@code @timestamp} in ISO-8601 UTC, the startup line secret-free and field-complete, the bind
 * accept/reject lines carrying the contract fields, PDU bodies TRACE-gated (off by default) and the
 * bind password absent at ANY level.
 *
 * <p><b>The appender under test is the SHIPPED one, not a copy.</b> The tier's plain
 * {@code logback-test.xml} (which keeps {@code OutputCapture} assertions matching raw text) masks the
 * production shape for every other test &mdash; so this suite arms the REAL encoder three ways:
 * <ol>
 *   <li>a source pin on {@code logback-spring.xml} (encoder class, UTC, the ISO pattern, the INFO
 *       root &mdash; the {@code MetricsEndpointTest} source-pin idiom);</li>
 *   <li>a FULL boot under {@code --logging.config=classpath:logback-spring.xml} with stdout swapped
 *       into memory &mdash; Spring re-initializes logback from the production file, so EVERY boot line
 *       (framework noise included) must come out one-parseable-object-per-line;</li>
 *   <li>an in-memory capture appender REUSING the file-configured {@code LogstashEncoder} (loaded
 *       through {@link JoranConfigurator} from the classpath resource, then detached from the console
 *       and re-streamed into a sink) while the REAL fire sites are driven through the embedded-pair
 *       harness &mdash; the accept at the ROK couple, the reject at the AD-33 deny plane, the TRACE
 *       bodies at {@code relayFramedPdu} (the {@code ThrowingObserverHardeningTest} fixture mirror;
 *       the relay package's {@code CoupledPairHarness} is package-private).</li>
 * </ol>
 *
 * <p><b>Strict parsing via Nimbus</b> ({@link JSONObjectUtils#parse} &mdash; the security suites'
 * idiom): json-path's json-smart backend accepts garbage, which would make the every-line-parses
 * row vacuous; Nimbus rejects plain text and trailing garbage.
 *
 * <p>RED-on-neuter: flip the encoder/timeZone/pattern in {@code logback-spring.xml}, add a secret to
 * the startup summary, drop the bind-family redaction, or emit a non-JSON stdout line from the boot
 * &mdash; each turns exactly one row below red.
 */
@Tag("integration")
@Tag("observability")
@Tag("p1")
@DisplayName("StructuredLog — FR-OBS-2: stdout is JSON-lines (UTC ISO stamps, secret-free, TRACE-gated)")
class StructuredLogTest {

    private static final String PRODUCTION_CONFIG = "/logback-spring.xml";
    private static final String TEST_CONFIG = "/logback-test.xml";

    /** The production file's only appender name — the handle {@link #armProductionAppender} grabs. */
    private static final String CONSOLE_APPENDER = "CONSOLE";

    /**
     * The PDU-body TRACE logger's name &mdash; pinned as the LITERAL (the
     * {@code ThrowingObserverHardeningTest} idiom): the TRACE rows arm the level by this exact name,
     * so a rename of the production constant silently kills body logging and those rows go red.
     */
    private static final String PDU_BODY_LOGGER = "smpp.companion.proxy.relay.pdu";

    private static final int HEADER = 16;

    /** SMPP 3.4 §4.1.2 opaque PDU (never parsed by the codec) — a relaying stand-in with a body. */
    private static final int SUBMIT_SM = 0x00000004;

    private final ByteArrayOutputStream sink = new ByteArrayOutputStream();
    private final List<EmbeddedChannel> channels = new ArrayList<>();
    private final List<ByteBuf> toRelease = new ArrayList<>();
    private LoggerContext logback;

    @TempDir
    Path dir;

    @AfterEach
    void releaseChannelsAndBuffers() {
        channels.forEach(EmbeddedChannel::finishAndReleaseAll);
        channels.clear();
        toRelease.forEach(b -> {
            if (b.refCnt() > 0) {
                b.release();
            }
        });
        toRelease.clear();
    }

    // ---------- row 0: the shipped config pins the shape ------------------------------------

    @Test
    @DisplayName("logback-spring.xml pins the JSON-lines shape: LogstashEncoder, ISO_OFFSET_DATE_TIME, UTC, INFO root")
    void productionConfigPinsTheJsonLinesShape() throws IOException {
        String xml = readResource(PRODUCTION_CONFIG);
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
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
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
                        "companion.forward.mode-a.trust-store.path=" + legs.trustStore(),
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
        armProductionAppender();
        try {
            MeteredRelayObserver observer = new MeteredRelayObserver(
                    new PrometheusMeterRegistry(PrometheusConfig.DEFAULT), new RoutingTable(relayProperties()));

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
        armProductionAppender();
        ch.qos.logback.classic.Logger pduLogger =
                (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(PDU_BODY_LOGGER);
        Level original = pduLogger.getLevel();
        pduLogger.setLevel(Level.TRACE);
        try {
            MeteredRelayObserver observer = new MeteredRelayObserver(
                    new PrometheusMeterRegistry(PrometheusConfig.DEFAULT), new RoutingTable(relayProperties()));
            couple(observer);
            ingress.writeInbound(inbound(opaquePdu(SUBMIT_SM, 301)));
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
        armProductionAppender(); // the production config's own levels: root INFO, no TRACE anywhere
        try {
            MeteredRelayObserver observer = new MeteredRelayObserver(
                    new PrometheusMeterRegistry(PrometheusConfig.DEFAULT), new RoutingTable(relayProperties()));
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

    // ---------- the production appender under test -------------------------------------------

    /**
     * Reconfigures the JVM's logback from the PRODUCTION {@code logback-spring.xml} (classpath
     * resource), then re-streams the file-configured encoder into an in-memory appender: the shape
     * under test is the shipped one, not a test-side twin. The console appender is detached (its
     * encoder is borrowed, not copied) and the whole arrangement is undone by
     * {@link #restoreTestLogging()}.
     */
    private void armProductionAppender() {
        logback = (LoggerContext) LoggerFactory.getILoggerFactory();
        sink.reset();
        logback.reset();
        configure(PRODUCTION_CONFIG);
        ConsoleAppender<ILoggingEvent> console = (ConsoleAppender<ILoggingEvent>)
                logback.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME).getAppender(CONSOLE_APPENDER);
        assertThat(console).as("the production config declares the %s appender", CONSOLE_APPENDER).isNotNull();
        assertThat(console.getEncoder()).as("the production encoder is the logstash one")
                .isInstanceOf(net.logstash.logback.encoder.LogstashEncoder.class);
        OutputStreamAppender<ILoggingEvent> capture = new OutputStreamAppender<>();
        capture.setContext(logback);
        capture.setName("STRUCTURED_LOG_TEST_CAPTURE");
        capture.setEncoder(console.getEncoder()); // the SHIPPED encoder, shared (the console is detached)
        capture.setOutputStream(sink);
        capture.start();
        ch.qos.logback.classic.Logger root = logback.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
        root.addAppender(capture);
        root.detachAppender(console);
    }

    /** Restores the tier's plain {@code logback-test.xml} so later suites see the test console. */
    private void restoreTestLogging() {
        logback.reset();
        configure(TEST_CONFIG);
    }

    private void configure(String resource) {
        JoranConfigurator configurator = new JoranConfigurator();
        configurator.setContext(logback);
        try (InputStream in = StructuredLogTest.class.getResourceAsStream(resource)) {
            assertThat(in).as("classpath resource %s", resource).isNotNull();
            configurator.doConfigure(in);
        } catch (JoranException | IOException e) {
            throw new IllegalStateException("cannot configure logback from " + resource, e);
        }
    }

    // ---------- JSON-stream assertion helpers -------------------------------------------------

    /** Strict-parses EVERY captured line as one JSON object (Nimbus rejects plain text and garbage). */
    private List<Map<String, Object>> capturedJsonLines() {
        return parseEveryLine(sink.toString(StandardCharsets.UTF_8).lines()
                .map(String::trim).filter(s -> !s.isEmpty()).toList());
    }

    private static List<Map<String, Object>> parseEveryLine(List<String> lines) {
        List<Map<String, Object>> parsed = new ArrayList<>(lines.size());
        for (String line : lines) {
            try {
                parsed.add(JSONObjectUtils.parse(line));
            } catch (ParseException e) {
                fail("stdout line is not one JSON object (FR-OBS-2): <" + line + ">", e);
            }
        }
        return parsed;
    }

    /** Every line's {@code @timestamp} must be ISO-8601 with a UTC offset (a 'Z' or +00:00 render). */
    private static void assertUtcIsoStamps(List<Map<String, Object>> parsed) {
        for (Map<String, Object> line : parsed) {
            Object ts = line.get("@timestamp");
            assertThat(ts).as("@timestamp field on every line").isNotNull();
            OffsetDateTime stamp;
            try {
                stamp = OffsetDateTime.parse(String.valueOf(ts));
            } catch (DateTimeParseException e) {
                throw new AssertionError("@timestamp is not ISO-8601: <" + ts + ">", e);
            }
            assertThat(stamp.getOffset().getTotalSeconds())
                    .as("@timestamp offset is UTC (%s)", ts)
                    .isZero();
        }
    }

    private static Map<String, Object> lineByEvent(List<Map<String, Object>> lines, String event) {
        return lines.stream()
                .filter(line -> event.equals(line.get("event")))
                .findFirst()
                .orElseGet(() -> fail("no " + event + " line among " + lines.size() + " captured lines"));
    }

    private static String readResource(String resource) throws IOException {
        try (InputStream in = StructuredLogTest.class.getResourceAsStream(resource)) {
            assertThat(in).as("classpath resource %s", resource).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // ---------- the embedded-pair fixture (the ThrowingObserverHardeningTest mirror) -----------

    private ConnectionRegistry registry;
    private RelayStateManager manager;
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

    private EmbeddedChannel channel(ChannelHandler... handlers) {
        EmbeddedChannel channel = new EmbeddedChannel(DefaultChannelId.newInstance(), handlers);
        channels.add(channel); // released in @AfterEach however the row ends (exception-safe)
        return channel;
    }

    /** A verifier whose future is ALREADY settled to {@code DenyInvalid} (the committed deny idiom). */
    private static BindCredentialVerifier denyingVerifier() {
        return (BindCredential cred, ScopedValue<RequestContext> ctx) -> new VerdictRequest() {
            @Override
            public java.util.concurrent.CompletableFuture<Verdict> future() {
                return java.util.concurrent.CompletableFuture.completedFuture(new Verdict.DenyInvalid());
            }

            @Override
            public void cancelHttp() {
                // no wire call exists to cancel on this fixture
            }
        };
    }

    /** Releases whatever a channel's inbound queue holds (the EgressLeg-less ROK tail). */
    private static void drainInbound(EmbeddedChannel channel) {
        Object msg;
        while ((msg = channel.readInbound()) != null) {
            if (msg instanceof SmppBindPdu pdu) {
                pdu.originalFrame().release();
            } else if (msg instanceof ByteBuf buf) {
                buf.release();
            }
        }
    }

    // ---------- hand-authored PDU builders (raw bytes — independent of the codec) --------------

    private static byte[] bindRequest(int commandId, int sequence, String systemId, String password) {
        byte[] id = ascii(systemId);
        byte[] pw = ascii(password);
        byte[] type = ascii("SMPP");
        byte[] range = ascii("");
        int body = (id.length + 1) + (pw.length + 1) + (type.length + 1) + 3 + (range.length + 1);
        return assemble(commandId, 0, sequence, body, out -> {
            out.put(id).put((byte) 0);
            out.put(pw).put((byte) 0);
            out.put(type).put((byte) 0);
            out.put((byte) 0x34).put((byte) 0).put((byte) 0);
            out.put(range).put((byte) 0);
        });
    }

    private static byte[] bindResponse(int commandId, int sequence, int commandStatus, String systemId,
            byte[] tlvTail) {
        byte[] id = ascii(systemId);
        int body = (id.length + 1) + tlvTail.length;
        return assemble(commandId, commandStatus, sequence, body, out -> {
            out.put(id).put((byte) 0);
            out.put(tlvTail);
        });
    }

    /** An OPAQUE non-bind PDU: a valid 16-octet header + an arbitrary opaque body (never parsed). */
    private static byte[] opaquePdu(int commandId, int sequence) {
        byte[] body = new byte[] {0x01, 0x02, 0x03, 0x04};
        return assemble(commandId, 0, sequence, body.length, out -> out.put(body));
    }

    private interface BodyWriter {
        void writeTo(java.nio.ByteBuffer out);
    }

    private static byte[] assemble(int commandId, int commandStatus, int sequence, int bodyLen, BodyWriter writer) {
        java.nio.ByteBuffer out = java.nio.ByteBuffer.allocate(HEADER + bodyLen);
        out.putInt(HEADER + bodyLen).putInt(commandId).putInt(commandStatus).putInt(sequence);
        writer.writeTo(out);
        return out.array();
    }

    /** Lowercase hex of a PDU's bytes — the exact text {@code ByteBufUtil.hexDump} would emit. */
    private static String hex(byte[] pdu) {
        StringBuilder sb = new StringBuilder(pdu.length * 2);
        for (byte b : pdu) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private ByteBuf inbound(byte[] pdu) {
        ByteBuf buf = Unpooled.wrappedBuffer(pdu);
        toRelease.add(buf); // backstop release; the normal path releases via the pipeline
        return buf;
    }
}
