package smpp.companion.proxy.security;

/**
 * The single port that owns the SMPP bind-credential adjudication seam (AD-12). Implementations verify the
 * SMPP password-grant (ROPC) and return a {@link VerdictRequest} carrying the {@link Verdict}. The port is
 * swappable: {@code relay/} wires against {@link AlwaysAllowBindCredentialVerifier} until Epic 3 swaps in the
 * production ROPC adapter behind this UNCHANGED interface.
 *
 * <p>Runs on the relay's hand-managed virtual-thread pool (AD-6 / AD-28); <b>never {@code @Async}</b>. The
 * {@link ScopedValue} carries the per-bind {@link RequestContext} (context only, not control flow, AD-12).
 * Story 2.1 AC8 ratifies this exact shape (the "immutable henceforth" decision).
 */
public interface BindCredentialVerifier {

    /**
     * Adjudicate the bind credential. Returns a {@link VerdictRequest} exposing {@link VerdictRequest#future()}
     * (the {@link Verdict}) and {@link VerdictRequest#cancelHttp()} (abort the underlying HTTP call, AD-32).
     *
     * @param cred the bind credential to adjudicate; non-null.
     * @param ctx  the {@link ScopedValue} handle carrying the per-bind {@link RequestContext}; non-null.
     * @return a {@link VerdictRequest}; never {@code null}.
     */
    VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx);
}
