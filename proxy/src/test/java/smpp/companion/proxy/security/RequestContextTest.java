package smpp.companion.proxy.security;

import io.netty.channel.ChannelId;
import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AC1 / AD-5: {@link RequestContext} is the per-bind context bound via {@link java.lang.ScopedValue}
 * (never {@link ThreadLocal}) and threaded into {@code BindCredentialVerifier.verify}. It carries the
 * identity, the Netty ingress channel id (AD-8: {@code ConnectionRegistry} is keyed by ingress
 * {@link ChannelId}), and the adjudication deadline.
 *
 * <p>RED-on-neuter (AC9): drop a null guard and this test goes RED.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-5 RequestContext — per-bind context (systemId, ChannelId, deadline)")
class RequestContextTest {

    private RequestContext context() {
        return new RequestContext(
                new SystemId(new AsciiString("smsc-user")),
                DefaultChannelId.newInstance(),
                Instant.now().plusSeconds(5));
    }

    @Test
    @DisplayName("carries systemId, Netty ChannelId, and an Instant adjudication deadline")
    void carriesTheThreeFields() {
        RequestContext ctx = context();
        assertThat((CharSequence) ctx.systemId().value()).isEqualTo(new AsciiString("smsc-user"));
        assertThat(ctx.channelId()).isInstanceOf(ChannelId.class);
        assertThat(ctx.deadline()).isInstanceOf(Instant.class);
    }

    @Test
    @DisplayName("rejects null systemId (AD-35 @NullMarked)")
    void rejectsNullSystemId() {
        assertThatThrownBy(() -> new RequestContext(
                null, DefaultChannelId.newInstance(), Instant.now()))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("systemId");
    }

    @Test
    @DisplayName("rejects null channelId (AD-35 @NullMarked)")
    void rejectsNullChannelId() {
        assertThatThrownBy(() -> new RequestContext(
                new SystemId(new AsciiString("u")), null, Instant.now()))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("channelId");
    }

    @Test
    @DisplayName("rejects null deadline (AD-35 @NullMarked)")
    void rejectsNullDeadline() {
        assertThatThrownBy(() -> new RequestContext(
                new SystemId(new AsciiString("u")), DefaultChannelId.newInstance(), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("deadline");
    }
}
