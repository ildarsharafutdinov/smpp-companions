package smpp.companion.codec.command;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-026..029: {@code SmppCommandIds} is the AD-27 single source of truth for the parsed-vs-opaque
 * boundary. These cover the command-id <em>membership</em> and <em>response-bit identity</em> aspects
 * of CODEC-026 / 027 / 028 / 029.
 *
 * <p>The <em>parser-behavior</em> halves of CODEC-027 / 028 — "the bind parser emits no typed object
 * for outbind / generic_nack / non-bind command_ids" — land with the bind parser in T3
 * (CODEC-016..023, CODEC-037); there is no parser to assert against in T1.
 *
 * <p>Spec reconciliation #1 (Story 1.2 "Read first"): {@code bind_transceiver = 0x00000009}, NOT
 * {@code 0x0F} (which is the {@code ESME_RINVSYSID} <em>status</em> code — the likely typo origin).
 * Verified against SMPP 3.4 Issue 1.2 §5.1.2 and the jSMPP 3.0.2 oracle (CODEC-031).
 */
@Tag("unit")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppCommandIds — bind-family command_id source of truth (CODEC-026..029)")
class SmppCommandIdsTest {

    @Test
    @DisplayName("CODEC-026: BIND_FAMILY is exactly the six spec-correct bind command_ids (0x09, not 0x0F)")
    void bindFamily_isExactlyTheSixSpecCorrectIds() {
        assertThat(SmppCommandIds.BIND_FAMILY)
                .containsExactlyInAnyOrder(
                        0x00000001, 0x00000002, 0x00000009,
                        0x80000001, 0x80000002, 0x80000009)
                .hasSize(6);
    }

    @Test
    @DisplayName("CODEC-026: the three bind requests and their three responses are all members")
    void bindFamily_containsAllThreeRequestsAndTheirResponses() {
        assertThat(SmppCommandIds.BIND_FAMILY)
                .contains(
                        SmppCommandIds.BIND_RECEIVER,
                        SmppCommandIds.BIND_TRANSMITTER,
                        SmppCommandIds.BIND_TRANSCEIVER,
                        SmppCommandIds.BIND_RECEIVER_RESP,
                        SmppCommandIds.BIND_TRANSMITTER_RESP,
                        SmppCommandIds.BIND_TRANSCEIVER_RESP);
    }

    @Test
    @DisplayName("CODEC-027: outbind (0x0B) and generic_nack (0x80000000) are NOT bind-family (opaque-spliced)")
    void outbindAndGenericNack_areNotBindFamily() {
        assertThat(SmppCommandIds.isBindFamily(0x0000000B)).isFalse(); // outbind
        assertThat(SmppCommandIds.isBindFamily(0x80000000)).isFalse(); // generic_nack
    }

    @Test
    @DisplayName("CODEC-028: non-bind command_ids (submit_sm/deliver_sm/enquire_link/unbind) are NOT bind-family")
    void nonBindCommandIds_areNotBindFamily() {
        assertThat(SmppCommandIds.isBindFamily(0x00000004)).isFalse(); // submit_sm
        assertThat(SmppCommandIds.isBindFamily(0x00000005)).isFalse(); // deliver_sm
        assertThat(SmppCommandIds.isBindFamily(0x00000015)).isFalse(); // enquire_link
        assertThat(SmppCommandIds.isBindFamily(0x00000006)).isFalse(); // unbind
    }

    @Test
    @DisplayName("CODEC-029: response bit distinguishes bind request from bind_resp; both bind-family")
    void responseBit_distinguishesRequestFromResponse() {
        // transceiver request AND response are both recognized as bind-family
        assertThat(SmppCommandIds.isBindFamily(0x00000009)).isTrue();
        assertThat(SmppCommandIds.isBindFamily(0x80000009)).isTrue();

        // bit-31 predicate (requests have it clear; responses have it set)
        assertThat(SmppCommandIds.isResponse(0x00000009)).isFalse();
        assertThat(SmppCommandIds.isResponse(0x00000002)).isFalse();
        assertThat(SmppCommandIds.isResponse(0x80000009)).isTrue();
        assertThat(SmppCommandIds.isResponse(0x80000002)).isTrue();

        // clearing bit 31 yields the underlying request id; masking never conflates request with response
        assertThat(SmppCommandIds.requestIdOf(0x80000009)).isEqualTo(0x00000009);
        assertThat(SmppCommandIds.requestIdOf(0x00000009)).isEqualTo(0x00000009); // identity for requests
        assertThat(SmppCommandIds.requestIdOf(0x80000002)).isEqualTo(0x00000002);
    }

    @Test
    @DisplayName("bit-31 predicate pinned at boundary values (0x80000000 / 0x00000000 / 0xFFFFFFFF)")
    void responseBit_predicateAtBoundaryValues() {
        // generic_nack (0x80000000) carries the response bit but is NOT bind-family (opaque, AD-32);
        // isResponse is a pure bit-test, so it is true regardless of bind-family membership.
        assertThat(SmppCommandIds.isResponse(0x80000000)).isTrue();
        assertThat(SmppCommandIds.isBindFamily(0x80000000)).isFalse();

        // 0x00000000 (unassigned) and 0xFFFFFFFF (bit-31 set) — isResponse is a pure bit-test
        assertThat(SmppCommandIds.isResponse(0x00000000)).isFalse();
        assertThat(SmppCommandIds.isResponse(0xFFFFFFFF)).isTrue();

        // requestIdOf on generic_nack clears bit 31 -> 0x00000000 (unassigned; no underlying request).
        // Documented behavior (undefined outside the bind-family response set), not a routed value.
        assertThat(SmppCommandIds.requestIdOf(0x80000000)).isEqualTo(0x00000000);
    }
}
