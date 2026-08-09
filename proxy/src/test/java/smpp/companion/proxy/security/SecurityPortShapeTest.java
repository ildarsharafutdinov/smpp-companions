package smpp.companion.proxy.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.lang.ScopedValue;
import java.lang.reflect.Method;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC1 / AD-12: ratify the EXACT port shape by reflection. The opener's deliverable is "the port contract,
 * validated before it is consumed" — so the seam signatures are pinned here exactly as AD-12 / AD-32 state:
 *
 * <ul>
 *   <li>{@code BindCredentialVerifier}: {@code VerdictRequest verify(BindCredential, ScopedValue<RequestContext>)};</li>
 *   <li>{@code VerdictRequest}: {@code CompletableFuture<Verdict> future()} + {@code void cancelHttp()}
 *       (AD-32 — the handle aborts the underlying HTTP ROPC call, not only the future).</li>
 * </ul>
 *
 * <p>Generic erasure means reflection sees {@code ScopedValue} / {@code CompletableFuture} raw; the
 * parameter/return CLASSes and arity are what we pin. RED-on-neuter (AC9): rename a method, change a
 * parameter/return type, or drop {@code cancelHttp()} and this test goes RED.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-12/AD-32 port shape — verify(BindCredential, ScopedValue) : VerdictRequest{future, cancelHttp}")
class SecurityPortShapeTest {

    @Test
    @DisplayName("BindCredentialVerifier is an interface with exactly one method: verify")
    void verifierShape() throws NoSuchMethodException {
        assertThat(BindCredentialVerifier.class.isInterface()).isTrue();
        // Exactly the verify seam — no extra public methods on the port interface.
        assertThat(BindCredentialVerifier.class.getDeclaredMethods()).hasSize(1);

        Method verify = BindCredentialVerifier.class.getDeclaredMethod(
                "verify", BindCredential.class, ScopedValue.class);
        assertThat(verify.getReturnType())
                .as("verify must return VerdictRequest (the future()+cancelHttp() handle)")
                .isEqualTo(VerdictRequest.class);
        var params = verify.getParameterTypes();
        assertThat(params).containsExactly(BindCredential.class, ScopedValue.class);
    }

    @Test
    @DisplayName("VerdictRequest exposes CompletableFuture<Verdict> future() AND void cancelHttp() (AD-32)")
    void verdictRequestShape() throws NoSuchMethodException {
        assertThat(VerdictRequest.class.isInterface()).isTrue();
        assertThat(VerdictRequest.class.getDeclaredMethods())
                .as("VerdictRequest carries exactly the future() + cancelHttp() handles")
                .hasSize(2);

        Method future = VerdictRequest.class.getDeclaredMethod("future");
        assertThat(future.getReturnType())
                .as("future() returns CompletableFuture<Verdict> (raw CompletableFuture under erasure)")
                .isEqualTo(CompletableFuture.class);

        Method cancelHttp = VerdictRequest.class.getDeclaredMethod("cancelHttp");
        assertThat(cancelHttp.getReturnType())
                .as("cancelHttp() returns void — it aborts the wire call, returns nothing")
                .isEqualTo(void.class);
    }
}
