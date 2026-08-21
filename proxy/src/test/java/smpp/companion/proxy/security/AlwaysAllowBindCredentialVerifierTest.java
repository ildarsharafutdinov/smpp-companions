package smpp.companion.proxy.security;

import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Component;

import java.lang.ScopedValue;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC1 / AD-12 (amended 2026-08-18): {@link AlwaysAllowBindCredentialVerifier} is the FORWARD-cell
 * stand-in {@link BindCredentialVerifier} (the trusted-side relay adjudicates nothing); the reverse
 * cells get the ROPC adapter. Since Story 3.2 T7 it is NOT self-annotated {@code @Component} — its
 * wiring moved to {@code VerifierWiringConfig} (an unconditional component would make every reverse
 * context carry TWO verifier beans); {@code VerifierWiringConfigTest} pins the selection. Its
 * {@code verify} returns a {@link VerdictRequest} already completed with {@link Verdict.Allow} and
 * its {@code cancelHttp()} is a no-op (an always-allow never starts a wire call, so there is
 * nothing to abort).
 *
 * <p>RED-on-neuter (AC9): make {@code verify} deny, return an uncompleted future, or throw from
 * {@code cancelHttp} and a test below goes RED.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-12 AlwaysAllowBindCredentialVerifier — wired (not annotated) stand-in, completed-Allow, no-op cancel")
class AlwaysAllowBindCredentialVerifierTest {

    /** ScopedValue handle — the stand-in ignores it (the real adapter reads the bound context). */
    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    private static BindCredential credential() {
        return new BindCredential(new SystemId(new AsciiString("smsc-user")), new Password(new AsciiString("pw")));
    }

    @Test
    @DisplayName("is NOT self-annotated @Component — its wiring moved to VerifierWiringConfig (T7, AC1)")
    void isNotSelfAnnotatedComponent() {
        assertThat(AlwaysAllowBindCredentialVerifier.class.isAnnotationPresent(Component.class))
                .as("an unconditional @Component would collide with the adapter on reverse cells — "
                        + "the per-cell selection lives in VerifierWiringConfig (AC1)")
                .isFalse();
        assertThat(AlwaysAllowBindCredentialVerifier.class.getInterfaces())
                .contains(BindCredentialVerifier.class);
    }

    @Test
    @DisplayName("verify returns a VerdictRequest whose future is ALREADY completed with Allow")
    void verifyReturnsCompletedAllow() {
        var verifier = new AlwaysAllowBindCredentialVerifier();
        VerdictRequest request = verifier.verify(credential(), CTX);

        CompletableFuture<Verdict> future = request.future();
        assertThat(future).isCompleted();
        assertThat(future.isCompletedExceptionally())
                .as("always-allow completes normally, never exceptionally")
                .isFalse();
        assertThat(future.join()).isEqualTo(new Verdict.Allow());
    }

    @Test
    @DisplayName("cancelHttp is a no-op and leaves the completed-Allow future intact")
    void cancelHttpIsNoOp() {
        var verifier = new AlwaysAllowBindCredentialVerifier();
        VerdictRequest request = verifier.verify(credential(), CTX);

        // An always-allow never starts a wire call, so cancelHttp must not throw or alter the verdict.
        request.cancelHttp();
        assertThat(request.future()).isCompleted();
        assertThat(request.future().join()).isEqualTo(new Verdict.Allow());
    }

    @Test
    @DisplayName("verify is deterministic across calls — always Allow (no verdict cache concern; the value is constant)")
    void verifyIsDeterministic() {
        var verifier = new AlwaysAllowBindCredentialVerifier();
        Verdict a = verifier.verify(credential(), CTX).future().join();
        Verdict b = verifier.verify(credential(), CTX).future().join();
        assertThat(a).isEqualTo(b).isEqualTo(new Verdict.Allow());
    }

    @Test
    @DisplayName("the RequestContext handle is accepted (port signature compiles; stand-in does not read it)")
    void acceptsScopedRequestContext() {
        var verifier = new AlwaysAllowBindCredentialVerifier();
        RequestContext rc = new RequestContext(
                new SystemId(new AsciiString("smsc-user")),
                DefaultChannelId.newInstance(),
                Instant.now().plusSeconds(5));
        // Binding the context in a scope models real relay usage; the stand-in ignores it but the call must succeed.
        ScopedValue.where(CTX, rc).run(() -> {
            VerdictRequest request = verifier.verify(credential(), CTX);
            assertThat(request.future().join()).isEqualTo(new Verdict.Allow());
        });
    }
}
