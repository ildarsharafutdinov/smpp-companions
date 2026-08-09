package smpp.companion.proxy.security;

import java.util.concurrent.CompletableFuture;

/**
 * The handle returned by {@link BindCredentialVerifier#verify} (AD-12 / AD-32). Exposes both the
 * {@link CompletableFuture} that completes with the {@link Verdict} <b>and</b> {@code cancelHttp()} — the
 * handle that aborts the <em>underlying HTTP ROPC call</em>, not only the future (AD-32). The ROPC adapter
 * binds {@code cancelHttp()} to the {@code HttpClient} exchange abort so AD-32 case-3 teardown spares the IdP
 * the abandoned ROPC call (the IdP-amplification mitigation otherwise unreachable through the seam).
 *
 * <p>Cancelling {@link #future()} does NOT by itself abort the wire call; callers that need to stop the in-
 * flight ROPC request (e.g. on bind teardown) must invoke {@link #cancelHttp()}. The validation slice
 * (Story 2.1 Task 2) provides the test-tier implementation; the production ROPC adapter (Epic 3) provides it
 * behind this UNCHANGED interface.
 */
public interface VerdictRequest {

    /**
     * The {@link CompletableFuture} carrying the adjudication {@link Verdict}.
     *
     * @return the future completing with the {@link Verdict}; never {@code null}.
     */
    CompletableFuture<Verdict> future();

    /**
     * Abort the underlying HTTP ROPC call (AD-32). Idempotent: a no-op once the call has already completed or
     * been cancelled. Returns nothing; the {@link Verdict} (if any) is observed via {@link #future()}.
     */
    void cancelHttp();
}
