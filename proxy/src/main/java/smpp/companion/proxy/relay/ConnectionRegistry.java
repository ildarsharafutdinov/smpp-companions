package smpp.companion.proxy.relay;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import io.netty.channel.Channel;
import io.netty.channel.ChannelId;
import io.netty.util.AttributeKey;

import smpp.companion.proxy.security.SystemId;

/**
 * The single concurrent bean that owns ALL mutable per-bind runtime state (AD-8). Keyed by ingress
 * {@link ChannelId}; each {@link ConnectionEntry} holds the coupled-pair state (peer-egress {@link Channel},
 * the AD-25 couple flag, session metadata, tearing-down mark, and — since Story 3.4 T6 — the in-flight
 * adjudication handles: pending {@code VerdictRequest} + pending {@code Password}). A {@link Channel}
 * attribute caches the entry on
 * BOTH legs for O(1) event-loop access (no map probe on the hot path). Teardown removes via
 * {@link #beginTeardown(Channel)} on either leg (idempotent &mdash; RELAY-005); egress-connect failure after
 * the entry was optimistically created removes it and hands the ingress back to the caller to close
 * (RELAY-006).
 *
 * <p><b>Holds NO {@code message_id}&rarr;{@code system_id} mapping</b> (REL-4 / RELAY-025) &mdash; socket-pairing
 * state only; DLRs ride the coupled channel (AD-9). The structural RELAY-025 scan forbids that
 * identifier/map from ever appearing in {@code relay/}.
 *
 * <p><b>Bean:</b> a singleton {@link Component @Component}. Since Story 3.4 T6 the production state machine
 * runs through the {@code RelayStateManager} bean wrapped over THIS storage (the transition policy sits over
 * the registry — AD-8's named home; {@code BindInterceptor} / the per-leg relay handlers inject the manager,
 * which is the shape AD-8's 2026-08-29 amendment records); the registry remains directly testable and its
 * CAS-once teardown mechanics are the manager's substrate. Holds no other state, so
 * {@code new ConnectionRegistry()} is the test seam.
 *
 * <p><b>Enumeration (Story 4.3 T1):</b> {@link #snapshot()} exposes the live pairs to the AD-22 drain body
 * as read-only {@link LivePair} projections. ALL mutation stays on {@link #register} / {@link #attachEgress} /
 * {@link #beginTeardown} (with the ENTRY attribute sets/clears they carry — the key is private, so fencing
 * the three methods fences the attribute writes too), whose only production caller is the
 * {@code RelayStateManager} — an invariant the {@code ConnectionRegistryMutationFenceArchitectureTest}
 * ArchUnit fence pins.
 */
@Component
public final class ConnectionRegistry {

    /**
     * The map keyed by ingress {@link ChannelId} (never by {@code message_id} &mdash; REL-4 / RELAY-025). The
     * only {@link java.util.Map} in {@code relay/}; the RELAY-025 scan asserts it is {@link ChannelId}-keyed.
     */
    private final ConcurrentHashMap<ChannelId, ConnectionEntry> entries = new ConcurrentHashMap<>();

    /** Caches the entry on both legs for O(1) event-loop access (AD-8). */
    private static final AttributeKey<ConnectionEntry> ENTRY = AttributeKey.valueOf(ConnectionRegistry.class, "entry");

    /**
     * Optimistically register a new coupled pair at bind arrival (the entry exists BEFORE the egress connects
     * &mdash; RELAY-006). Caches the entry on the ingress channel; the egress leg is attached later via
     * {@link #attachEgress(ChannelId, Channel)} once it connects.
     *
     * @param ingress  the legacy-client-facing leg; non-null.
     * @param systemId the identity forwarded end-to-end (AD-14); non-null.
     * @return the new entry (also cached on the ingress attribute).
     */
    public ConnectionEntry register(Channel ingress, SystemId systemId) {
        ConnectionEntry entry = new ConnectionEntry(ingress.id(), ingress, systemId);
        ingress.attr(ENTRY).set(entry);
        entries.put(ingress.id(), entry);
        return entry;
    }

    /**
     * Attach the SMSC-facing leg once it connects. Caches the entry on the egress channel too, so
     * {@link #entryFor(Channel)} resolves from either leg. No-op if the entry is already gone (the ingress
     * tore down during the egress handshake). Write-once per live entry (a re-bind is a new entry).
     *
     * @param ingressId the ingress {@link ChannelId} that keys the entry; non-null.
     * @param egress    the SMSC-facing leg; non-null.
     */
    public void attachEgress(ChannelId ingressId, Channel egress) {
        ConnectionEntry entry = entries.get(ingressId);
        if (entry != null) {
            entry.attach(egress);
            egress.attr(ENTRY).set(entry);
        }
    }

    /**
     * O(1) entry lookup from either leg (reads the cached attribute; no map probe). Returns {@code null} once
     * teardown has cleared the attribute, so a racing callback observes "absent" and no-ops (AC3).
     *
     * @param channel either the ingress or egress leg; non-null.
     * @return the entry cached on this channel, or {@code null} if none (no bind, or already torn down).
     */
    public @Nullable ConnectionEntry entryFor(Channel channel) {
        return channel.attr(ENTRY).get();
    }

    /**
     * Begin teardown of the pair reachable from this leg (AD-32 race-free teardown: remove + mark tearing-down
     * BEFORE close). Idempotent (RELAY-005): the first caller wins the {@link ConnectionEntry#beginTearingDown()}
     * CAS and owns the teardown side-effects (close both legs, {@code cancelHttp}, {@code zeroize}); every
     * later caller &mdash; the losing leg's {@code channelInactive}, the AD-25 Deny-callback, the AD-32
     * violation handler &mdash; gets {@code null} and MUST no-op.
     *
     * <p>Reads the cached attribute (not the map) so a leg whose attribute was already cleared by the winner
     * observes {@code null} before it even reaches the CAS &mdash; the single-threaded double-teardown
     * fast path. The CAS is the race-free guarantee when both legs' attributes are still set.
     *
     * @param channel either leg of the pair; non-null.
     * @return the entry if THIS call won the race (perform the side-effects), or {@code null} if the pair is
     *         unknown here or teardown already began.
     */
    public @Nullable ConnectionEntry beginTeardown(Channel channel) {
        ConnectionEntry entry = channel.attr(ENTRY).get();
        if (entry == null) {
            return null;
        }
        if (!entry.beginTearingDown()) {
            return null;
        }
        // Won the race: drop from the registry, clear BOTH legs' attributes, hand the entry to the caller.
        entries.remove(entry.ingressId());
        clearAttributes(entry);
        return entry;
    }

    private static void clearAttributes(ConnectionEntry entry) {
        entry.ingress().attr(ENTRY).set(null);
        Channel egress = entry.egress();
        if (egress != null) {
            egress.attr(ENTRY).set(null);
        }
    }

    /** The number of live coupled pairs (test observation / AD-22 drain enumeration). */
    public int size() {
        return entries.size();
    }

    /**
     * The AD-22 drain enumeration (Story 4.3): a point-in-time, read-only snapshot of every live pair, each
     * row a {@link LivePair} projection &mdash; never the {@link ConnectionEntry} itself, whose package-private
     * adjudication handles and teardown CAS must not escape {@code relay/}'s mutation paths (the drain body
     * closes legs through the {@code RelayStateManager}, keeping the mutation fence intact). Weakly consistent
     * with the underlying map: pairs registered or torn down after the call neither appear in nor vanish from
     * the returned list, and the list rejects mutation itself. Iteration order is unspecified &mdash; callers
     * must not depend on it.
     *
     * @return an unmodifiable snapshot of the live pairs at call time; empty when the registry is empty.
     */
    public List<LivePair> snapshot() {
        return entries.values().stream()
                .map(entry -> new LivePair(entry.ingress(), entry.egress(), entry.systemId()))
                .toList();
    }

    /**
     * One row of the {@link #snapshot()} drain enumeration: a read-only projection of a live pair's two legs
     * and its identity. Deliberately NOT a {@link ConnectionEntry} &mdash; the entry carries the package-private
     * in-flight adjudication handles ({@code VerdictRequest} / {@code Password}) and the tearing-down CAS, so
     * handing entries past the registry would widen mutation access the Story 4.3 mutation fence exists to
     * deny.
     *
     * @param ingress  the legacy-client-facing leg; non-null.
     * @param egress   the SMSC-facing leg, or {@code null} while the egress connect is still pending (the
     *                 optimistic-entry window, RELAY-006).
     * @param systemId the identity forwarded end-to-end (AD-14); non-null.
     */
    public record LivePair(Channel ingress, @Nullable Channel egress, SystemId systemId) {
    }
}
