package smpp.companion.proxy.relay;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;

import org.jsmpp.bean.BindType;
import org.jsmpp.bean.BroadcastSm;
import org.jsmpp.bean.CancelBroadcastSm;
import org.jsmpp.bean.CancelSm;
import org.jsmpp.bean.DataCodings;
import org.jsmpp.bean.DataSm;
import org.jsmpp.bean.ESMClass;
import org.jsmpp.bean.InterfaceVersion;
import org.jsmpp.bean.NumberingPlanIndicator;
import org.jsmpp.bean.OptionalParameter;
import org.jsmpp.bean.QueryBroadcastSm;
import org.jsmpp.bean.QuerySm;
import org.jsmpp.bean.RegisteredDelivery;
import org.jsmpp.bean.ReplaceSm;
import org.jsmpp.bean.SubmitMulti;
import org.jsmpp.bean.SubmitSm;
import org.jsmpp.bean.TypeOfNumber;
import org.jsmpp.extra.ProcessRequestException;
import org.jsmpp.session.BindRequest;
import org.jsmpp.session.BroadcastSmResult;
import org.jsmpp.session.DataSmResult;
import org.jsmpp.session.QueryBroadcastSmResult;
import org.jsmpp.session.QuerySmResult;
import org.jsmpp.session.SMPPServerSession;
import org.jsmpp.session.SMPPServerSessionListener;
import org.jsmpp.session.ServerMessageReceiverListener;
import org.jsmpp.session.Session;
import org.jsmpp.session.SubmitMultiResult;
import org.jsmpp.session.SubmitSmResult;
import org.jsmpp.util.MessageId;

import smpp.companion.proxy.testsupport.RelayTestFixtures;

/**
 * The T10 jSMPP 3.0.2 server-side mock SMSC — the INDEPENDENT A-1 conformance oracle (OBS-038,
 * AD-24). Unlike {@link MockSmsc} (the production-codec mock, which is NEVER an oracle), this
 * fixture is a full second SMPP stack: every PDU the relay splices onto an egress socket is
 * <b>parsed by jSMPP</b>, and every PDU the legacy client receives from a pair was
 * <b>constructed by jSMPP</b> — it shares NEITHER the production codec's bugs NOR its framing
 * assumptions. If the relay (or the production framer/codec behind it) mis-frames, mis-parses,
 * or cross-couples anything on either leg, this stack rejects or garbles the exchange and the
 * test goes RED — that is the oracle property RELAY-011's in-JVM mock cannot have.
 *
 * <p><b>Programming (the T10 subtask's list):</b> SMPP is one-bind-per-connection by spec, so the
 * affinity scenario is N separate connections sharing one {@code system_id}: the accept loop
 * yields one {@link SMPPServerSession} per TCP connection, {@code waitForBind()} delivers each
 * {@link BindRequest}, and every {@code bind_transceiver} is ROK'd <b>regardless of
 * {@code system_id}</b> ({@code accept("jsmpp-smpp", IF_34)}). On a decoded {@code submit_sm} the
 * carrier-side affinity fires: a tagged {@code deliver_sm} (DLR) is emitted on the SAME session
 * the submit arrived on — the socket-pairing behavior A-1 claims the real carrier exhibits
 * (jSMPP deciding the socket is the independent part; the relay must merely preserve it).
 *
 * <p><b>Honest scope (the story's load-bearing caveat):</b> this oracle proves A-1's mechanics in
 * CI against an independent stack — it does NOT prove a REAL carrier's affinity; that remains the
 * non-CI plan {@code docs/a-1-carrier-test-plan.md} (OBS-035/036/037).
 *
 * <p><b>Threading:</b> {@code deliverShortMessage} blocks for the {@code deliver_sm_resp}, so DLR
 * emission is scheduled on the fixture's own worker pool — never on jSMPP's PDU-reader thread
 * (blocking inside {@code onAcceptSubmitSm} would starve the session's own response processing).
 * The accept loop + workers are daemon threads; {@link #close()} closes the listener and every
 * session so jSMPP's per-session reader threads terminate with the test. Timers are quiet
 * ({@code enquire_link} 60s, transaction 5s): no proactive {@code enquire_link} from the SMSC
 * side racing the zero-cross-bleed assertions, and a generous window for the plain-socket client
 * to answer the DLR.
 *
 * <p>Test-tier only ({@code proxy/src/test}); loopback-reached over an ephemeral port (jSMPP's
 * listener API binds all interfaces — accepted for a short-lived test fixture; the production
 * bind-host posture is Epic 3, per the T6 review). Plaintext (TLS is Epic 3).
 */
public final class JsmppSmscServer implements AutoCloseable {

    /** Bounded-poll deadline for the await helpers (generous for a loaded CI runner). */
    private static final long AWAIT_TIMEOUT_MILLIS = 5_000;

    /** The window a connection has to send its bind after TCP accept (jSMPP initiation). */
    private static final long BIND_WINDOW_MILLIS = 10_000;

    /** Quiet timers: no proactive enquire_link racing the assertions; a generous resp window. */
    private static final int ENQUIRE_LINK_TIMER_MILLIS = 60_000;
    private static final long TRANSACTION_TIMER_MILLIS = 5_000;

    /** ESME_RSYSERR 0x00000008 — the generic status for operations the fixture does not program. */
    private static final int UNSUPPORTED_COMMAND_STATUS = 0x00000008;

    /** The ESME_RSYSERR-bearing rejection every non-submit_sm operation gets (only submit is programmed). */
    private static final String ONLY_SUBMIT_IS_PROGRAMMED =
            "the oracle fixture programs bind + submit_sm only";

    private static final String SMSC_SYSTEM_ID = "jsmpp-smpp";

    private final SMPPServerSessionListener listener;
    private final ExecutorService workers;
    private final List<BoundSession> sessions = new CopyOnWriteArrayList<>();
    private final ConcurrentLinkedQueue<SubmittedSm> submits = new ConcurrentLinkedQueue<>();
    /** Bind/accept/delivery anomalies — a healthy run accumulates NONE (the test asserts this). */
    private final ConcurrentLinkedQueue<Exception> anomalies = new ConcurrentLinkedQueue<>();
    private final AtomicLong messageIds = new AtomicLong();
    private volatile boolean closed;

    private JsmppSmscServer(SMPPServerSessionListener listener, ExecutorService workers) {
        this.listener = listener;
        this.workers = workers;
    }

    /**
     * Starts the oracle on a free ephemeral port and begins accepting connections. The port is
     * probed first (the {@link RelayTestFixtures#freePort()} TOCTOU-accepted practice) because
     * jSMPP's {@code getPort()} returns the CONFIGURED port, not the live bound one — a
     * {@code new SMPPServerSessionListener(0)} binds an ephemeral port yet keeps reporting 0,
     * which would send the relay's egress at port 0 (refused connect → AD-33 deny).
     */
    public static JsmppSmscServer start() {
        SMPPServerSessionListener listener;
        try {
            listener = new SMPPServerSessionListener(RelayTestFixtures.freePort());
        } catch (IOException e) {
            throw new UncheckedIOException("cannot bind the jSMPP oracle listener", e);
        }
        ExecutorService workers = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "jsmpp-oracle-worker");
            thread.setDaemon(true);
            return thread;
        });
        JsmppSmscServer oracle = new JsmppSmscServer(listener, workers);
        Thread acceptLoop = new Thread(oracle::acceptLoop, "jsmpp-oracle-accept");
        acceptLoop.setDaemon(true);
        acceptLoop.start();
        return oracle;
    }

    /** The port the oracle's listener bound (reach it via loopback). */
    public int port() {
        return listener.getPort();
    }

    /** The bound sessions, in accept order (one per connection the relay egressed). */
    public List<BoundSession> sessions() {
        return List.copyOf(sessions);
    }

    /** Waits (bounded) for at least {@code n} sessions to have completed their bind handshake. */
    public List<BoundSession> awaitSessions(int n) {
        pollUntil(() -> sessions.size() >= n);
        return sessions();
    }

    /** Every captured {@code submit_sm}, in arrival order (the affinity bookkeeping). */
    public List<SubmittedSm> submits() {
        return List.copyOf(submits);
    }

    /** Waits (bounded) for at least {@code n} captured submits, then returns the captures. */
    public List<SubmittedSm> awaitSubmits(int n) {
        pollUntil(() -> submits.size() >= n);
        return submits();
    }

    /** Anomalies accumulated on the SMSC side (bind/accept/delivery failures) — empty on a healthy run. */
    public List<Exception> anomalies() {
        return List.copyOf(anomalies);
    }

    @Override
    public void close() {
        closed = true;
        try {
            listener.close();
        } catch (IOException ignored) {
            // best-effort teardown — the test owns the assertions, not the mock's shutdown
        }
        sessions.forEach(session -> closeQuietly(session.session()));
        workers.shutdownNow();
    }

    // ---------- internals ----------

    private void acceptLoop() {
        while (!closed) {
            try {
                SMPPServerSession session = listener.accept();
                workers.execute(() -> handleSession(session));
            } catch (IOException e) {
                if (!closed) {
                    anomalies.add(e);
                }
                return; // the listener is gone — nothing more to accept
            }
        }
    }

    private void handleSession(SMPPServerSession session) {
        session.setMessageReceiverListener(messageReceiver());
        session.setEnquireLinkTimer(ENQUIRE_LINK_TIMER_MILLIS);
        session.setTransactionTimer(TRANSACTION_TIMER_MILLIS);
        try {
            BindRequest request = session.waitForBind(BIND_WINDOW_MILLIS);
            // ROK regardless of system_id — one-bind-per-connection, any number of concurrent
            // connections may share one system_id (A-1's premise, accepted by the oracle).
            request.accept(SMSC_SYSTEM_ID, InterfaceVersion.IF_34);
            sessions.add(new BoundSession(session, request.getSystemId(), request.getBindType()));
        } catch (TimeoutException | IllegalStateException e) {
            // A connection that never completed its bind (or raced the fixture's close) — not a
            // scenario failure; the paired test's own read would time out if this was its leg.
            closeQuietly(session);
        } catch (Exception e) {
            anomalies.add(e);
            closeQuietly(session);
        }
    }

    /** The carrier-side behavior: ROK'd binds + DLR emission on the session a submit arrived on. */
    private ServerMessageReceiverListener messageReceiver() {
        return new ServerMessageReceiverListener() {
            @Override
            public SubmitSmResult onAcceptSubmitSm(SubmitSm submitSm, SMPPServerSession source) {
                byte[] shortMessage = submitSm.getShortMessage() == null ? new byte[0] : submitSm.getShortMessage();
                submits.add(new SubmittedSm(source, shortMessage));
                // Carrier affinity: the DLR leaves on the SAME session the submit arrived on —
                // scheduled OFF the PDU-reader thread (deliverShortMessage blocks for the resp).
                workers.execute(() -> deliverDlrOn(source, shortMessage));
                try {
                    return new SubmitSmResult(
                            new MessageId("oracle-" + messageIds.incrementAndGet()), new OptionalParameter[0]);
                } catch (org.jsmpp.PDUStringException e) {
                    throw new IllegalStateException("fixture message id failed jSMPP validation", e);
                }
            }

            @Override
            public SubmitMultiResult onAcceptSubmitMulti(SubmitMulti submitMulti, SMPPServerSession source)
                    throws ProcessRequestException {
                throw unsupported();
            }

            @Override
            public QuerySmResult onAcceptQuerySm(QuerySm querySm, SMPPServerSession source)
                    throws ProcessRequestException {
                throw unsupported();
            }

            @Override
            public void onAcceptReplaceSm(ReplaceSm replaceSm, SMPPServerSession source)
                    throws ProcessRequestException {
                throw unsupported();
            }

            @Override
            public void onAcceptCancelSm(CancelSm cancelSm, SMPPServerSession source)
                    throws ProcessRequestException {
                throw unsupported();
            }

            @Override
            public BroadcastSmResult onAcceptBroadcastSm(BroadcastSm broadcastSm, SMPPServerSession source)
                    throws ProcessRequestException {
                throw unsupported();
            }

            @Override
            public void onAcceptCancelBroadcastSm(CancelBroadcastSm cancelBroadcastSm, SMPPServerSession source)
                    throws ProcessRequestException {
                throw unsupported();
            }

            @Override
            public QueryBroadcastSmResult onAcceptQueryBroadcastSm(
                    QueryBroadcastSm queryBroadcastSm, SMPPServerSession source)
                    throws ProcessRequestException {
                throw unsupported();
            }

            @Override
            public DataSmResult onAcceptDataSm(DataSm dataSm, Session source) throws ProcessRequestException {
                throw unsupported();
            }
        };
    }

    /**
     * Emits the tagged DLR on the given session — jSMPP CONSTRUCTS the {@code deliver_sm} bytes
     * (the independence: what the legacy client then reads was built by the second stack), and
     * blocks until the client's {@code deliver_sm_resp} arrives (or the transaction timer).
     */
    private void deliverDlrOn(SMPPServerSession session, byte[] submittedShortMessage) {
        String tag = new String(submittedShortMessage, StandardCharsets.US_ASCII);
        byte[] dlr = ("DLR:" + tag).getBytes(StandardCharsets.US_ASCII);
        try {
            session.deliverShortMessage(
                    "dlr",
                    TypeOfNumber.UNKNOWN, NumberingPlanIndicator.UNKNOWN, SMSC_SYSTEM_ID,
                    TypeOfNumber.UNKNOWN, NumberingPlanIndicator.UNKNOWN, "legacy1",
                    new ESMClass(0x04), // SMSC delivery receipt (the DLR shape)
                    (byte) 0,
                    (byte) 0,
                    new RegisteredDelivery((byte) 0),
                    DataCodings.ZERO,
                    dlr);
        } catch (Exception e) {
            anomalies.add(e);
        }
    }

    private static ProcessRequestException unsupported() {
        return new ProcessRequestException(ONLY_SUBMIT_IS_PROGRAMMED, UNSUPPORTED_COMMAND_STATUS);
    }

    private static void closeQuietly(SMPPServerSession session) {
        try {
            session.close();
        } catch (RuntimeException ignored) {
            // best-effort teardown of a session that never fully established
        }
    }

    /** Bounded poll — the fixture's await discipline (never an unbounded sleep in a test). */
    private static void pollUntil(BooleanSupplier condition) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(AWAIT_TIMEOUT_MILLIS);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException(
                        "jSMPP oracle condition not reached within " + AWAIT_TIMEOUT_MILLIS + "ms");
            }
            sleepQuietly(10);
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while awaiting the jSMPP oracle", e);
        }
    }

    /** One bound SMSC-side session: the jSMPP session + the bind the oracle observed on it. */
    public record BoundSession(SMPPServerSession session, String systemId, BindType bindType) { }

    /** One captured submit: the session it arrived on + the short_message tag it carried. */
    public record SubmittedSm(SMPPServerSession session, byte[] shortMessage) { }
}
