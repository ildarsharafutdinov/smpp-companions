package smpp.companion.proxy.observability;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;

import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Component;

import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC5 / AD-27: {@link RelayObserver} is the observability seam the relay fires against a coupled
 * ingress&harr;egress pair. Its SHAPE is the load-bearing invariant (2.1 scoped it OUT; 2.2 authors it;
 * Epic 4 swaps the impl only), so this test pins the shape by reflection &mdash; mirroring
 * {@code VerdictShapeTest} / {@code SecurityPortShapeTest}:
 *
 * <ul>
 *   <li>exactly 4 methods &mdash; no PDU type, no content (only {@link Direction} / {@link SystemId} /
 *       {@link Verdict} / {@link CloseReason} cross the seam &mdash; AD-19 cardinality bound, AD-27
 *       codec-emits-no-metrics; PDU count is observed by counting {@link RelayObserver#onFramedPdu(Direction)}
 *       fires, so the seam carries no byte-volume signal);</li>
 *   <li>{@link Direction} = the closed 2-value set {INGRESS, EGRESS};</li>
 *   <li>{@link CloseReason} = the closed 16-value set, exhaustive over the spine's close paths
 *       (AD-27 gate-fix {@code .memlog.md:96});</li>
 *   <li>the {@code observability} package is {@link NullMarked} (AD-35 &mdash; the annotation does NOT
 *       propagate);</li>
 *   <li>{@link NoopRelayObserver} is the seeded {@link Component @Component} default bean, final.</li>
 * </ul>
 *
 * <p>RED-on-neuter (AC9 / AI-1): add / drop / rename a method (incl. reintroducing a byte/transfer method),
 * add a 17th {@link CloseReason} or a 3rd {@link Direction}, un-{@link NullMarked} the package, or strip
 * {@link Component @Component} and this test fails. (The formal consolidated mutation pass is T11; the
 * assertions here bite by construction.)
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@DisplayName("AD-27 RelayObserver — 4-method seam + closed Direction(2)/CloseReason(16) sets + @NullMarked")
class RelayObserverShapeTest {

    @Test
    @DisplayName("RelayObserver is an interface with exactly 4 declared methods")
    void relayObserverIsFourMethodInterface() {
        assertThat(RelayObserver.class.isInterface())
                .as("RelayObserver must be an interface (Epic 4 swaps the impl behind it)").isTrue();
        assertThat(RelayObserver.class.getDeclaredMethods())
                .as("RelayObserver carries exactly the 4 pinned triggers — no PDU type, no content, no byte-volume (AD-27)")
                .hasSize(4);
    }

    @Test
    @DisplayName("onFramedPdu(Direction) : void — opaque framing, no type/body (PDU count = fires)")
    void onFramedPduSignature() throws NoSuchMethodException {
        Method m = RelayObserver.class.getDeclaredMethod("onFramedPdu", Direction.class);
        assertThat(m.getReturnType())
                .as("onFramedPdu returns void").isEqualTo(void.class);
        assertThat(m.getParameterTypes())
                .as("onFramedPdu takes only Direction (no PDU type, no content)").containsExactly(Direction.class);
    }

    @Test
    @DisplayName("onBindAccept(SystemId) : void — at the AD-25 ROK couple, not the verdict")
    void onBindAcceptSignature() throws NoSuchMethodException {
        Method m = RelayObserver.class.getDeclaredMethod("onBindAccept", SystemId.class);
        assertThat(m.getReturnType()).isEqualTo(void.class);
        assertThat(m.getParameterTypes())
                .as("onBindAccept takes only SystemId (identity, at the couple)").containsExactly(SystemId.class);
    }

    @Test
    @DisplayName("onBindReject(SystemId, Verdict) : void — imports proxy.security.Verdict (AD-33)")
    void onBindRejectSignature() throws NoSuchMethodException {
        Method m = RelayObserver.class.getDeclaredMethod("onBindReject", SystemId.class, Verdict.class);
        assertThat(m.getReturnType()).isEqualTo(void.class);
        assertThat(m.getParameterTypes())
                .as("onBindReject takes SystemId + the security.Verdict (no reason string)").containsExactly(SystemId.class, Verdict.class);
    }

    @Test
    @DisplayName("onConnectionClosed(Direction, CloseReason) : void — exactly-once per channel")
    void onConnectionClosedSignature() throws NoSuchMethodException {
        Method m = RelayObserver.class.getDeclaredMethod("onConnectionClosed", Direction.class, CloseReason.class);
        assertThat(m.getReturnType()).isEqualTo(void.class);
        assertThat(m.getParameterTypes())
                .as("onConnectionClosed takes Direction + CloseReason").containsExactly(Direction.class, CloseReason.class);
    }

    @Test
    @DisplayName("Direction is the closed 2-value enum {INGRESS, EGRESS}")
    void directionIsClosedTwoValueSet() {
        assertThat(Direction.values())
                .as("Direction is the closed 2-value set over the spine's legs")
                .containsExactly(Direction.INGRESS, Direction.EGRESS);
    }

    @Test
    @DisplayName("CloseReason is the closed 16-value set, exhaustive over the spine's close paths")
    void closeReasonIsClosedSixteenValueSet() {
        assertThat(CloseReason.values())
                .as("AD-27 gate-fix .memlog.md:96 pins exactly 16 close paths")
                .hasSize(16);
        var names = Arrays.stream(CloseReason.values()).map(Enum::name).toList();
        assertThat(names)
                .as("the 16 close paths verbatim (AC5)")
                .containsExactlyInAnyOrder(
                        "PEER_HALF_CLOSE", "PEER_RST", "EGRESS_CONNECT_FAILED",
                        "OVERSIZED_FRAME", "UNDERSIZED_FRAME", "DECODE_ERROR",
                        "UNKNOWN_COMMAND_ID", "PRE_COUPLE_NON_BIND_PDU", "CLEAN_UNBIND_HANDSHAKE",
                        "GENERIC_NACK_PRE_BIND", "BIND_REJECTED", "BIND_FAILED_NON_ROK",
                        "INGRESS_TLS_HANDSHAKE_FAILED", "EGRESS_TLS_HANDSHAKE_FAILED",
                        "SHUTDOWN_DRAIN", "OTHER");
    }

    @Test
    @DisplayName("the observability package is @NullMarked (AD-35)")
    void packageIsNullMarked() {
        assertThat(RelayObserver.class.getPackage().isAnnotationPresent(NullMarked.class))
                .as("observability must be @NullMarked (AD-35 — the annotation does NOT propagate)")
                .isTrue();
    }

    @Test
    @DisplayName("NoopRelayObserver is a final @Component implementing RelayObserver (the default bean)")
    void noopObserverIsDefaultComponent() {
        assertThat(RelayObserver.class.isAssignableFrom(NoopRelayObserver.class))
                .as("NoopRelayObserver must implement RelayObserver").isTrue();
        assertThat(NoopRelayObserver.class.isAnnotationPresent(Component.class))
                .as("NoopRelayObserver must be @Component (the injectable default bean; Epic 4 swaps the impl)")
                .isTrue();
        assertThat(Modifier.isFinal(NoopRelayObserver.class.getModifiers()))
                .as("NoopRelayObserver must be final (mirror AlwaysAllowBindCredentialVerifier)").isTrue();
    }
}
