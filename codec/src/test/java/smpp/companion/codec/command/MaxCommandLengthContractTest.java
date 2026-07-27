package smpp.companion.codec.command;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RELAY-026 (stub) / AD-30: the codec's {@code MAX_COMMAND_LENGTH} is the single named constant that
 * the future relay direct-memory formula input AND the Story 1.3 config default MUST reference, so the
 * codec max and the allocator budget can never drift apart.
 *
 * <p><b>Stub scope (Story 1.2 / T1):</b> only the codec constant exists today — assert its pinned value.
 *
 * <p><b>Full three-way assertion (Story 1.3):</b> once {@code companion.*} config keys and the
 * {@code MaxDirectMemorySize = max_frame × max_inbound_depth × concurrent_pairs × safety_factor}
 * formula land, assert codec-constant ≡ formula-input ≡ config-default all resolve to ONE value.
 * Tracked in {@code deferred-work.md}.
 *
 * <p>See Story 1.2 AC4 / AD-30 and {@code test-coverage-scenarios.md} RELAY-026.
 */
@Tag("unit")
@Tag("codec")
@Tag("p1")
@DisplayName("RELAY-026 stub — AD-30 shared max-frame constant contract")
class MaxCommandLengthContractTest {

    @Test
    @DisplayName("MAX_COMMAND_LENGTH == 65536 (AD-30 cap; covers message_payload TLV max)")
    void maxCommandLength_isPinnedAt65536() {
        assertThat(SmppCommandIds.MAX_COMMAND_LENGTH).isEqualTo(65536);
        assertThat(SmppCommandIds.MAX_COMMAND_LENGTH).isEqualTo(0x00010000);
    }
}
