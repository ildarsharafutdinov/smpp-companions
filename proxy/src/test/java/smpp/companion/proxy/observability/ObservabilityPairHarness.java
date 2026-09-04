package smpp.companion.proxy.observability;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.util.JSONObjectUtils;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.OutputStreamAppender;
import ch.qos.logback.core.joran.spi.JoranException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.embedded.EmbeddedChannel;

import smpp.companion.codec.bind.SmppBindPdu;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * The shared fixture of the observability-side suites ({@code ThrowingObserverHardeningTest},
 * {@code StructuredLogTest}, {@code StartupSummaryLoggerTest}) &mdash; the observability-package
 * mirror of {@code relay/}'s {@code CoupledPairHarness} (which is package-private over there, which
 * is why this twin exists at all). Owns, once:
 *
 * <ul>
 *   <li>the hand-authored wire-PDU builders ({@code bindRequest}/{@code bindResponse}/{@code
 *       opaquePdu}/{@code assemble}) and the {@link #hex} mirror of {@code ByteBufUtil.hexDump}
 *       &mdash; independent of the codec under test, the {@code BindInterceptorTest} idiom;</li>
 *   <li>the channel/buffer bookkeeping ({@link #channel(ChannelHandler...)}, {@link #inbound(byte[])}
 *       &mdash; read-out ownership stays with the taker; the backstop release runs in
 *       {@link #drainAndRelease()} however a row ends, exception-safe);</li>
 *   <li>the deny-plane verifier double ({@link #denyingVerifier()}) and the EgressLeg-less ROK tail
 *       release ({@link #drainInbound(EmbeddedChannel)});</li>
 *   <li>the PRODUCTION-log capture ({@link #armProductionJsonAppender()} /
 *       {@link #restoreTestLogging()} / {@link #capturedJsonLines()}): the appender under test is
 *       the SHIPPED {@code logback-spring.xml} one (loaded from the classpath resource through
 *       {@link JoranConfigurator}, its encoder re-streamed into an in-memory sink), so JSON-shape
 *       assertions run against the production encoder, not a test-side twin. Exception-safe by
 *       construction (step-04 review, finding #19): everything after the context reset is guarded
 *       &mdash; a mid-arm failure restores the tier's plain {@code logback-test.xml} before
 *       rethrowing, so later suites never inherit the production logback.</li>
 * </ul>
 *
 * <p><b>Strict parsing via Nimbus</b> ({@link JSONObjectUtils#parse} &mdash; the security suites'
 * idiom): json-path's json-smart backend silently accepts garbage, which would make every
 * every-line-parses assertion vacuous; Nimbus rejects plain text and trailing garbage.
 */
abstract class ObservabilityPairHarness {

    /** The production JSON-lines config (main resources — on the test classpath). */
    private static final String PRODUCTION_LOGBACK = "/logback-spring.xml";

    /** The tier's plain console config, restored by {@link #restoreTestLogging()}. */
    private static final String TEST_LOGBACK = "/logback-test.xml";

    /** The production file's only appender name — the handle {@link #armProductionJsonAppender()} grabs. */
    private static final String CONSOLE_APPENDER = "CONSOLE";

    /**
     * The PDU-body TRACE logger's name &mdash; pinned as the LITERAL (the
     * {@code MetricsEndpointTest} source-pin idiom, runtime flavor): TRACE rows arm the level by
     * this exact name, so a rename of the production constant silently kills body logging and those
     * rows go red.
     */
    protected static final String PDU_BODY_LOGGER = "smpp.companion.proxy.relay.pdu";

    protected static final int HEADER = 16;

    /** SMPP 3.4 §4.1.2 opaque PDU (never parsed by the codec) — a relaying stand-in with a body. */
    protected static final int SUBMIT_SM = 0x00000004;

    /**
     * A non-existent DLR command id (NOT the real deliver_sm 0x00000005) — guarantees no endpoint
     * ever parses the frame (the {@code CoupledPairHarness} note).
     */
    protected static final int OPAQUE_DLR_TAG = 0x00000105;

    /** The in-memory stdout of the armed production appender (JSON lines). */
    protected final ByteArrayOutputStream sink = new ByteArrayOutputStream();

    private final List<EmbeddedChannel> channels = new ArrayList<>();
    private final List<ByteBuf> toRelease = new ArrayList<>();

    private LoggerContext logback;

    @AfterEach
    void drainAndRelease() {
        channels.forEach(EmbeddedChannel::finishAndReleaseAll);
        channels.clear();
        toRelease.forEach(b -> {
            if (b.refCnt() > 0) {
                b.release();
            }
        });
        toRelease.clear();
    }

    // ---------- channel/buffer bookkeeping ----------------------------------------------------

    /** An embedded channel with a unique id (the T4 singleton-id trap), tracked for @AfterEach. */
    protected EmbeddedChannel channel(ChannelHandler... handlers) {
        EmbeddedChannel channel = new EmbeddedChannel(io.netty.channel.DefaultChannelId.newInstance(), handlers);
        channels.add(channel); // released in @AfterEach however the row ends (exception-safe)
        return channel;
    }

    protected ByteBuf inbound(byte[] pdu) {
        ByteBuf buf = Unpooled.wrappedBuffer(pdu);
        toRelease.add(buf); // backstop release; the normal path releases via the pipeline
        return buf;
    }

    /** Releases whatever a channel's inbound queue holds (the EgressLeg-less ROK tail). */
    protected static void drainInbound(EmbeddedChannel channel) {
        Object msg;
        while ((msg = channel.readInbound()) != null) {
            if (msg instanceof SmppBindPdu pdu) {
                pdu.originalFrame().release();
            } else if (msg instanceof ByteBuf buf) {
                buf.release();
            }
        }
    }

    /** A verifier whose future is ALREADY settled to {@code DenyInvalid} (the committed deny idiom). */
    protected static BindCredentialVerifier denyingVerifier() {
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

    // ---------- the production-log capture -----------------------------------------------------

    /**
     * Reconfigures the JVM's logback from the PRODUCTION {@code logback-spring.xml} (classpath
     * resource), then re-streams the file-configured encoder into an in-memory appender: the shape
     * under test is the shipped one, not a test-side twin. The console appender is detached (its
     * encoder is borrowed, not copied) and the whole arrangement is undone by
     * {@link #restoreTestLogging()} &mdash; which ALSO runs on a mid-arm failure (the context reset
     * happens before anything can throw, so the catch restores the tier's config before rethrowing:
     * later suites never inherit the production logback).
     */
    protected final void armProductionJsonAppender() {
        logback = (LoggerContext) LoggerFactory.getILoggerFactory();
        sink.reset();
        logback.reset(); // the shared context is being mutated from here on — guard the rest
        try {
            configureLogback(PRODUCTION_LOGBACK);
            ConsoleAppender<ILoggingEvent> console = (ConsoleAppender<ILoggingEvent>)
                    logback.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME)
                            .getAppender(CONSOLE_APPENDER);
            assertThat(console).as("the production config declares the %s appender", CONSOLE_APPENDER).isNotNull();
            assertThat(console.getEncoder()).as("the production encoder is the logstash one")
                    .isInstanceOf(net.logstash.logback.encoder.LogstashEncoder.class);
            OutputStreamAppender<ILoggingEvent> capture = new OutputStreamAppender<>();
            capture.setContext(logback);
            capture.setName("OBSERVABILITY_TEST_JSON_CAPTURE");
            capture.setEncoder(console.getEncoder()); // the SHIPPED encoder, shared (console detached)
            capture.setOutputStream(sink);
            capture.start();
            ch.qos.logback.classic.Logger root = logback.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
            root.addAppender(capture);
            root.detachAppender(console);
        } catch (RuntimeException | Error e) {
            restoreTestLogging();
            throw e;
        }
    }

    /** Restores the tier's plain {@code logback-test.xml} so later suites see the test console. */
    protected final void restoreTestLogging() {
        if (logback == null) {
            return; // never armed — nothing to restore
        }
        logback.reset();
        configureLogback(TEST_LOGBACK);
    }

    private void configureLogback(String resource) {
        JoranConfigurator configurator = new JoranConfigurator();
        configurator.setContext(logback);
        try (InputStream in = ObservabilityPairHarness.class.getResourceAsStream(resource)) {
            assertThat(in).as("classpath resource %s", resource).isNotNull();
            configurator.doConfigure(in);
        } catch (JoranException | IOException e) {
            throw new IllegalStateException("cannot configure logback from " + resource, e);
        }
    }

    // ---------- JSON-stream assertion helpers --------------------------------------------------

    /** Strict-parses EVERY captured line as one JSON object (Nimbus rejects plain text and garbage). */
    protected final List<Map<String, Object>> capturedJsonLines() {
        return parseEveryLine(sink.toString(StandardCharsets.UTF_8).lines()
                .map(String::trim).filter(s -> !s.isEmpty()).toList());
    }

    protected static List<Map<String, Object>> parseEveryLine(List<String> lines) {
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
    protected static void assertUtcIsoStamps(List<Map<String, Object>> parsed) {
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

    protected static Map<String, Object> lineByEvent(List<Map<String, Object>> lines, String event) {
        return lines.stream()
                .filter(line -> event.equals(line.get("event")))
                .findFirst()
                .orElseGet(() -> fail("no " + event + " line among " + lines.size() + " captured lines"));
    }

    // ---------- hand-authored PDU builders (raw bytes — independent of the codec) --------------

    protected static byte[] bindRequest(int commandId, int sequence, String systemId, String password) {
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

    protected static byte[] bindResponse(int commandId, int sequence, int commandStatus, String systemId,
            byte[] tlvTail) {
        byte[] id = ascii(systemId);
        int body = (id.length + 1) + tlvTail.length;
        return assemble(commandId, commandStatus, sequence, body, out -> {
            out.put(id).put((byte) 0);
            out.put(tlvTail);
        });
    }

    /** An OPAQUE non-bind PDU: a valid 16-octet header + an arbitrary opaque body (never parsed). */
    protected static byte[] opaquePdu(int commandId, int sequence) {
        byte[] body = new byte[] {0x01, 0x02, 0x03, 0x04};
        return assemble(commandId, 0, sequence, body.length, out -> out.put(body));
    }

    protected interface BodyWriter {
        void writeTo(java.nio.ByteBuffer out);
    }

    protected static byte[] assemble(int commandId, int commandStatus, int sequence, int bodyLen, BodyWriter writer) {
        java.nio.ByteBuffer out = java.nio.ByteBuffer.allocate(HEADER + bodyLen);
        out.putInt(HEADER + bodyLen).putInt(commandId).putInt(commandStatus).putInt(sequence);
        writer.writeTo(out);
        return out.array();
    }

    /** Lowercase hex of a PDU's bytes — the exact text {@code ByteBufUtil.hexDump} would emit. */
    protected static String hex(byte[] pdu) {
        StringBuilder sb = new StringBuilder(pdu.length * 2);
        for (byte b : pdu) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }
}
