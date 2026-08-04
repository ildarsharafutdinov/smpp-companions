package smpp.companion.codec.command;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import smpp.companion.codec.framer.SmppFrame;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RELAY-026 (stub) / AD-30: the codec's {@code MAX_COMMAND_LENGTH} is the single named constant that
 * the future relay direct-memory formula input AND the Story 1.3 config default MUST reference, so the
 * codec max and the allocator budget can never drift apart.
 *
 * <p><b>Codec pin (Story 1.2 / T1):</b> asserts the codec constant's pinned value — the
 * constant-side anchor of the RELAY-026 contract.
 *
 * <p><b>Proxy-side guard (Story 1.3):</b> {@code smpp.companion.proxy.config.Relay026ConstantContractTest}
 * guards that the proxy references this ONE named constant (no magic {@code 65536} literal); the
 * formula ({@code MemoryBudget}) uses it directly. {@code max-frame}/{@code max-command-length} are not
 * config keys &mdash; they can only be this constant. This codec pin stays as the constant-side anchor.
 *
 * <p>See Story 1.2 AC4 / AD-30 and {@code test-coverage-scenarios.md} RELAY-026.
 */
@Tag("unit")
@Tag("codec")
@Tag("p1")
@DisplayName("RELAY-026 — AD-30 shared max-frame constant contract (codec pin)")
class MaxCommandLengthContractTest {

    @Test
    @DisplayName("MAX_COMMAND_LENGTH == 65536 (AD-30 cap; covers message_payload TLV max)")
    void maxCommandLength_isPinnedAt65536() {
        assertThat(SmppFrame.MAX_COMMAND_LENGTH).isEqualTo(65536);
        assertThat(SmppFrame.MAX_COMMAND_LENGTH).isEqualTo(0x00010000);
    }
}
