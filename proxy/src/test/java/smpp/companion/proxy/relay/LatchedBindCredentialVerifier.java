package smpp.companion.proxy.relay;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;

/**
 * The relay tests' fake {@link BindCredentialVerifier} (RELAY-004's prescribed tooling: "a fake
 * verifier with {@code CountDownLatch}-held verdict, configurable {@code Allow} OR {@code Deny}").
 * The verdict future is held until the test completes it ({@link #completeAllow()} /
 * {@link #completeDeny(Verdict)}), so a test can park a bind mid-adjudication, inject a retry bind,
 * close a leg, or verify the no-op-after-teardown contract. Records every adjudicated
 * {@link BindCredential} (for the zeroize assertions — the caller-owned wipe must zero the SAME
 * backing array the verifier captured) and every {@link VerdictRequest#cancelHttp()} call (the
 * AD-32 teardown arm).
 *
 * <p>Test-tier only ({@code proxy/src/test}); the production default bean is
 * {@code AlwaysAllowBindCredentialVerifier}. Reused by T8/T9 relay tests.
 */
final class LatchedBindCredentialVerifier implements BindCredentialVerifier {

    private final CompletableFuture<Verdict> verdict = new CompletableFuture<>();

    /** Every credential handed to the verifier, in arrival order (zeroize assertions read these). */
    final List<BindCredential> capturedCredentials = new CopyOnWriteArrayList<>();

    /**
     * Every adjudication deadline the relay bound into the {@code ScopedValue} at each {@code verify}
     * call ({@code ctx.get().deadline()} — readable because the relay binds the scope AROUND the call).
     * The T7 owner-FIXME round asserts the configured {@code companion.bind.adjudication-deadline} flows
     * end-to-end into the port.
     */
    final List<java.time.Instant> capturedDeadlines = new CopyOnWriteArrayList<>();

    /** How many times the relay invoked {@link VerdictRequest#cancelHttp()} (the AD-32 teardown arm). */
    final AtomicInteger cancelHttpCalls = new AtomicInteger();

    private final VerdictRequest request = new VerdictRequest() {
        @Override
        public CompletableFuture<Verdict> future() {
            return verdict;
        }

        @Override
        public void cancelHttp() {
            cancelHttpCalls.incrementAndGet();
        }
    };

    @Override
    public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
        capturedCredentials.add(cred);
        capturedDeadlines.add(ctx.get().deadline());
        return request;
    }

    /** Settles the adjudication with {@link Verdict.Allow} (the wired default bean's outcome). */
    void completeAllow() {
        verdict.complete(new Verdict.Allow());
    }

    /** Settles the adjudication with the given deny {@link Verdict} ({@code DenyInvalid}/{@code DenyIndeterminate}). */
    void completeDeny(Verdict deny) {
        verdict.complete(deny);
    }

    /** Settles the adjudication EXCEPTIONALLY (a broken adapter — defense-in-depth, not the port's shape). */
    void completeExceptionally() {
        verdict.completeExceptionally(new IllegalStateException("adapter broke"));
    }
}
