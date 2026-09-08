package smpp.companion.proxy.relay;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;

import io.netty.buffer.ByteBuf;

import smpp.companion.codec.command.SmppCommandIds;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 4.3 T4 (OBS-017) &mdash; the new-adjudication gate at the interceptor level: once the shared
 * {@link NewAdjudicationGate} is armed (production arms it in {@code RelayServerLifecycle.stop()} at
 * the acceptor close &mdash; the arming and the real-socket wiring are {@code RelayServerLifecycleTest}'s
 * rows), a NEW bind on an established socket fail-closed-DENIES with the routing-miss arm's exact
 * shape: frame released, the AD-33 header-only deny answering the bind's identifiers, close &mdash; and
 * BEFORE {@code manager.register}, so no registry entry ever appears and the verifier is never
 * contacted (the bind never becomes an adjudication). The companion row pins the scope fence: an
 * armed gate leaves POST-COUPLE relaying untouched &mdash; the 4.3 drain body's premise (established
 * pairs must keep relaying until the deadline).
 *
 * <p>Rides the {@link CoupledPairHarness}: the REAL production ingress pipeline
 * ({@code framer → codec → BindInterceptor → RelayIngressHandler}) on an {@code EmbeddedChannel}
 * (an established socket by construction) with the latched verifier &mdash; its
 * {@code capturedCredentials} list IS the "verifier never contacted" observable.
 *
 * <p>RED-on-neuter: delete the {@code gate.armed()} check in {@code onRequest}'s first-bind arm and
 * row 1 fails three ways (no deny on the wire &mdash; the latched adjudication parks; a registry
 * entry; a captured verifier credential); widen the check to the post-couple arm and row 2 fails
 * (the drain premise).
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD) // the BindInterceptorTest pattern: a
// hung pipeline must FAIL a test, not hang the suite.
class NewAdjudicationGateTest extends CoupledPairHarness {

    @Test
    @DisplayName("OBS-017: with the gate armed, a bind on an established socket is denied fail-closed — "
            + "header-only non-ROK bind_resp, NO registry entry, NO verifier contact, frame released, "
            + "socket closed")
    void armedGateDeniesANewBindFailClosedWithoutVerifierContact() {
        gate.arm();
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 21, "legacy1", "pw123456"));
        ingress.writeInbound(frame);

        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the late bind is answered with the AD-33 generic deny").isNotNull();
        assertThat(deny.readableBytes()).as("header-only synth — the ONE PDU the relay builds").isEqualTo(HEADER);
        assertThat(deny.getInt(4)).as("bind_transceiver answered by bind_transceiver_resp")
                .isEqualTo(SmppCommandIds.BIND_TRANSCEIVER_RESP);
        assertThat(deny.getInt(8)).as("non-ROK: the AD-33 generic code, pinned as the literal (Q2)")
                .isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).as("the deny correlates the late bind's sequence_number").isEqualTo(21);
        deny.release(); // readOutbound hands the reader ownership (the T7 trap)
        assertThat(ingress.isOpen()).as("deny → then close").isFalse();
        assertThat(registry.size())
                .as("no registry entry — the gate denies BEFORE register (OBS-017)")
                .isZero();
        assertThat(verifier.capturedCredentials)
                .as("fail-closed DENY without contacting the verifier")
                .isEmpty();
        assertThat(observer.bindRejects())
                .as("the gate deny is not a returned Verdict — no onBindReject (AD-27)")
                .isEmpty();
        assertThat(frame.refCnt()).as("the late bind's original frame is released (never forwarded)").isZero();
    }

    @Test
    @DisplayName("an armed gate leaves POST-COUPLE relaying untouched — the drain body's premise (4.3 T5)")
    void armedGateLeavesPostCoupleRelayingUntouched() {
        couple();
        gate.arm();
        // (a) OPAQUE traffic — the drain plane's PDU shape (never parsed, never gate-visible).
        byte[] pdu = opaquePdu(SUBMIT_SM, 61);
        ingress.writeInbound(inbound(pdu));
        ByteBuf relayed = egress.readOutbound();
        assertThat(relayed).as("the coupled pair still relays after the gate armed").isNotNull();
        assertThat(bytesOf(relayed)).as("byte-exact — the gate is invisible on the relay plane").isEqualTo(pdu);
        relayed.release(); // readOutbound hands the reader ownership (the T7 trap)
        // (b) A decoded BIND-FAMILY PDU post-couple — the interceptor's dormant pass-through arm
        // itself (AD-2): a second bind on a coupled socket relays opaquely, so the drain keeps
        // carrying even the PDUs the gate's own first-bind arm would have denied pre-couple.
        byte[] lateBind = bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 62, "legacy1", "pw123456");
        ingress.writeInbound(inbound(lateBind));
        ByteBuf relayedBind = egress.readOutbound();
        assertThat(relayedBind).as("the post-couple bind still passes through the interceptor").isNotNull();
        assertThat(bytesOf(relayedBind)).as("byte-exact — no deny, no close, no re-adjudication")
                .isEqualTo(lateBind);
        relayedBind.release(); // readOutbound hands the reader ownership (the T7 trap)
        assertThat(registry.size()).as("the live pair is untouched by the gate").isEqualTo(1);
        assertThat(ingress.isOpen()).as("the ingress leg stays up — the drain owns its close").isTrue();
    }
}
