package smpp.companion.proxy.security;

import io.netty.channel.ChannelId;

import java.time.Instant;
import java.util.Objects;

/**
 * Per-bind context threaded into {@link BindCredentialVerifier#verify} via a {@link ScopedValue} (AD-5) —
 * <b>never a {@link ThreadLocal}</b>. Carries the identity, the Netty ingress channel id ({@link ChannelId};
 * AD-8 keys {@code ConnectionRegistry} by ingress {@code ChannelId}), and the absolute adjudication deadline.
 *
 * <p>{@code ScopedValue} carries per-bind context only, not control flow (AD-12); the scope's lifetime bounds
 * the adjudication fan-out, so a denied / timed-out / cancelled adjudication tears its tasks down with the
 * scope (no orphans, AD-5).
 *
 * @param systemId  the SMPP {@code system_id} for this bind; non-null.
 * @param channelId the Netty ingress channel id for this bind; non-null.
 * @param deadline  the absolute adjudication deadline (NTP-synced clock, A-4); the adapter derives per-call
 *                  timeouts from it; non-null.
 */
public record RequestContext(SystemId systemId, ChannelId channelId, Instant deadline) {

    public RequestContext {
        Objects.requireNonNull(systemId, "systemId");
        Objects.requireNonNull(channelId, "channelId");
        Objects.requireNonNull(deadline, "deadline");
    }
}
