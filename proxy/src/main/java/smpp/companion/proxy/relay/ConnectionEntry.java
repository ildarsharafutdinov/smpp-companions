package smpp.companion.proxy.relay;

import java.util.concurrent.atomic.AtomicBoolean;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import org.jspecify.annotations.Nullable;

import io.netty.channel.Channel;
import io.netty.channel.ChannelId;

import smpp.companion.proxy.security.SystemId;

/**
 * The ephemeral per-bind state for one coupled ingress&harr;egress pair (AD-8). One of these lives in the
 * {@link ConnectionRegistry} for the lifetime of a bind, cached on both legs' {@link Channel} attributes for
 * O(1) event-loop access. Holds exactly the four things AD-8 names &mdash; the peer-egress {@link Channel}
 * (absent until the egress connect succeeds; the entry is created optimistically at bind arrival per
 * RELAY-006), the AD-25 couple flag, the ephemeral session metadata ({@link SystemId} + the ingress
 * {@link ChannelId} that keys the registry), and the tearing-down mark &mdash; and NOTHING else. Specifically
 * it holds <b>no {@code message_id} correlation</b> (REL-4 / RELAY-025): socket-pairing state only; DLRs ride
 * the coupled channel (AD-9).
 *
 * <p><b>Thread-safety:</b> the couple flag and the tearing-down mark are {@link AtomicBoolean}s CASed exactly
 * once, so the two event loops (ingress + egress) and the AD-25 Deny-callback can race on teardown without
 * double-firing side-effects. {@link #beginTearingDown()} is the race-free guard the handlers re-check
 * (AC3); {@link #couple()} is the single AD-25 couple transition the {@code RelayEgressHandler} owns. The egress
 * channel is {@code volatile} (written once on the egress event loop, read on either). The {@link SystemId}
 * and ingress id are final (set at construction).
 *
 * <p>This type is relay-internal: {@code BindInterceptor} / the per-leg relay handlers (Story 2.2 T7 / T8,
 * split in Story 3.4 T5) read and couple it; it never crosses a package boundary (no metrics handle, no
 * observer payload).
 */
@Accessors(fluent = true)
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public final class ConnectionEntry {

    /** The ingress ChannelId that keys the ConnectionRegistry (AD-8). */
    @Getter
    private final ChannelId ingressId;
    /** The legacy-client-facing leg (read by the teardown path to close both legs, AD-32). */
    @Getter
    private final Channel ingress;
    /** The identity forwarded end-to-end (AD-14); carried for the onBindAccept/onBindReject triggers only (AD-19). */
    @Getter
    private final SystemId systemId;
    /** The SMSC-facing leg; null until the egress connect succeeds (optimistic creation, RELAY-006). */
    @Getter
    private volatile @Nullable Channel egress;
    private final AtomicBoolean coupled = new AtomicBoolean(false);
    private final AtomicBoolean tearingDown = new AtomicBoolean(false);

    /** Attach the SMSC-facing leg once it connects; package-private so it goes through {@link ConnectionRegistry}. */
    void attach(Channel egress) {
        this.egress = egress;
    }

    /** {@code true} iff the AD-25 couple fired on a decoded ROK {@code bind_*_resp} (the pair is relaying). */
    public boolean coupled() {
        return coupled.get();
    }

    /**
     * Couple the pair exactly once (AD-25 &mdash; the single couple unit is the {@code RelayEgressHandler}
     * on the ingress event loop; structural-by-type since the Story 3.4 T5 split, only that class calls
     * this). Returns {@code true} iff THIS call performed the transition; use that to fire
     * {@code onBindAccept} exactly at the couple (AC5), never at the verdict.
     *
     * @return {@code true} iff this call performed the couple (the pair transitioned to relaying).
     */
    public boolean couple() {
        return coupled.compareAndSet(false, true);
    }

    /** {@code true} iff teardown has begun on this pair (the re-check both Allow-couple and Deny-callback consult, AC3). */
    public boolean tearingDown() {
        return tearingDown.get();
    }

    /**
     * Mark this pair tearing-down, exactly once (AD-32 race-free teardown: remove + mark tearing-down BEFORE
     * close). Returns {@code true} iff THIS call won the race and owns the teardown side-effects (close both
     * legs, {@code cancelHttp}, {@code zeroize}); a losing caller MUST no-op. This is the idempotent-teardown
     * guard (RELAY-005) and the race-free re-check seam (AC3). CAS-once &mdash; neutering it (always returning
     * {@code true}) makes the RED-on-neuter test for the idempotent-teardown guard go RED.
     *
     * @return {@code true} iff this call won the teardown race.
     */
    public boolean beginTearingDown() {
        return tearingDown.compareAndSet(false, true);
    }
}
