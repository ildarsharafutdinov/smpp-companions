package smpp.companion.proxy.security;

import java.util.concurrent.CompletableFuture;

/**
 * The {@link BindCredentialVerifier} for <b>forward</b> cells (AD-12 amended 2026-08-18: the
 * forward role is a trusted-side relay that adjudicates nothing — the reverse role owns the ROPC
 * enforcement): always returns {@link Verdict.Allow} and never starts a wire call. NOT a Spring
 * {@code @Component} since Story 3.2 T7 — an unconditional component would collide with the ROPC
 * adapter in every reverse context; {@code VerifierWiringConfig} selects exactly one verifier bean
 * per cell (AC1) and wires this one on forward.mode-a/mode-c.
 */
public final class AlwaysAllowBindCredentialVerifier implements BindCredentialVerifier {

    private static final CompletableFuture<Verdict> COMPLETED_ALLOW =
            CompletableFuture.completedFuture(new Verdict.Allow());

    @Override
    public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
        return CompletedAllowVerdictRequest.INSTANCE;
    }

    /** A stateless {@link VerdictRequest} whose future is already completed with {@link Verdict.Allow}. */
    private static final class CompletedAllowVerdictRequest implements VerdictRequest {
        private static final CompletedAllowVerdictRequest INSTANCE = new CompletedAllowVerdictRequest();

        @Override
        public CompletableFuture<Verdict> future() {
            return COMPLETED_ALLOW;
        }

        @Override
        public void cancelHttp() {
            // No-op: an always-allow never starts a wire call, so there is nothing to abort (AD-32).
        }
    }
}
