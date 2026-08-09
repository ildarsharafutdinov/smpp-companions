package smpp.companion.proxy.security;

import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

/**
 * The production stand-in {@link BindCredentialVerifier} (AD-12): always returns {@link Verdict.Allow} and
 * never starts a wire call. This is what {@code relay/} wires against until Epic 3 swaps in the real ROPC
 * adapter behind the UNCHANGED port. A Spring {@link Component @Component} so it is injectable as the
 * default {@link BindCredentialVerifier} bean.
 */
@Component
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
