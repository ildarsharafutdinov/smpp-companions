package smpp.companion.proxy.relay;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import io.netty.channel.Channel;
import io.netty.channel.DefaultChannelId;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;

import smpp.companion.proxy.security.Password;
import smpp.companion.proxy.security.SystemId;

/**
 * AC1 / RELAY-005 / RELAY-006 &mdash; the {@link ConnectionRegistry} per-bind state contract (AD-8). Pins the
 * four things the entry holds and the three teardown invariants: (a) idempotent double-teardown on either leg
 * (RELAY-005), (b) caller-side password double-zeroize is safe (RELAY-005's R8 slice), (c) egress-connect
 * failure after an optimistic entry leaves no orphan (RELAY-006). The race-free CAS proof is a single-shot
 * two-leg race here; the statistical jcstress proof (RELAY-007) is deferred to the nightly hardening story
 * (see Completion Notes).
 *
 * <p><b>EmbeddedChannel + explicit {@link DefaultChannelId#newInstance()}:</b> the no-arg {@link EmbeddedChannel}
 * ctor historically shares a singleton {@code EmbeddedChannelId}, so every test channel is constructed with an
 * explicit unique id &mdash; the registry keys by {@code ChannelId} (AD-8) and a shared id would collide.
 */
@Tag("integration")
@Tag("relay")
@Tag("p1")
class ConnectionRegistryTest {

    /** A unique-id embedded channel (avoids the singleton EmbeddedChannelId collision on registry keys). */
    private static EmbeddedChannel channel() {
        return new EmbeddedChannel(DefaultChannelId.newInstance());
    }

    private static SystemId systemId(String value) {
        return new SystemId(AsciiString.of(value));
    }

    @Test
    @DisplayName("register creates an ingress-keyed entry, caches the attribute, and holds the four AD-8 fields")
    void registerCouplesIngressKeyedEntryAndCachesAttribute() {
        ConnectionRegistry registry = new ConnectionRegistry();
        EmbeddedChannel ingress = channel();

        ConnectionEntry entry = registry.register(ingress, systemId("legacy1"));

        assertThat(registry.size()).isEqualTo(1);
        assertThat(registry.entryFor(ingress)).isSameAs(entry);
        assertThat(entry.ingressId()).isEqualTo(ingress.id());
        assertThat(entry.ingress()).isSameAs(ingress);
        assertThat(entry.systemId()).isEqualTo(systemId("legacy1"));
        assertThat(entry.egress()).isNull();
        assertThat(entry.coupled()).isFalse();
        assertThat(entry.tearingDown()).isFalse();
    }

    @Test
    @DisplayName("distinct ingress channels get distinct registry keys (no ChannelId collision)")
    void distinctIngressChannelsAreDistinctKeys() {
        ConnectionRegistry registry = new ConnectionRegistry();
        EmbeddedChannel ingressA = channel();
        EmbeddedChannel ingressB = channel();

        ConnectionEntry entryA = registry.register(ingressA, systemId("legacyA"));
        ConnectionEntry entryB = registry.register(ingressB, systemId("legacyB"));

        assertThat(registry.size()).isEqualTo(2);
        assertThat(entryA).isNotSameAs(entryB);
        assertThat(registry.entryFor(ingressA)).isSameAs(entryA);
        assertThat(registry.entryFor(ingressB)).isSameAs(entryB);
    }

    @Test
    @DisplayName("attachEgress caches the entry on the egress leg too, so entryFor resolves from either leg")
    void attachEgressCachesAttributeOnBothLegs() {
        ConnectionRegistry registry = new ConnectionRegistry();
        EmbeddedChannel ingress = channel();
        EmbeddedChannel egress = channel();
        ConnectionEntry entry = registry.register(ingress, systemId("legacy1"));

        registry.attachEgress(ingress.id(), egress);

        assertThat(entry.egress()).isSameAs(egress);
        assertThat(registry.entryFor(egress)).isSameAs(entry);
        assertThat(registry.size()).isEqualTo(1);
    }

    @Test
    @DisplayName("attachEgress is a no-op when the ingress already tore down (no stale attribute written)")
    void attachEgressIsNoOpWhenIngressAlreadyGone() {
        ConnectionRegistry registry = new ConnectionRegistry();
        EmbeddedChannel ingress = channel();
        EmbeddedChannel egress = channel();
        registry.register(ingress, systemId("legacy1"));
        registry.beginTeardown(ingress); // ingress gone before the egress handshake completed

        registry.attachEgress(ingress.id(), egress);

        // No stale attribute written on the orphaned egress; registry still empty.
        assertThat(registry.entryFor(egress)).isNull();
        assertThat(registry.size()).isZero();
    }

    @Test
    @DisplayName("couple is CAS-once: exactly one caller performs the AD-25 couple")
    void coupleIsCasOnce() {
        ConnectionRegistry registry = new ConnectionRegistry();
        ConnectionEntry entry = registry.register(channel(), systemId("legacy1"));

        assertThat(entry.couple()).isTrue();
        assertThat(entry.couple()).isFalse();
        assertThat(entry.coupled()).isTrue();
    }

    @Test
    @DisplayName("beginTearingDown is CAS-once: exactly one caller owns teardown (the idempotent-teardown guard)")
    void beginTearingDownIsCasOnce() {
        ConnectionRegistry registry = new ConnectionRegistry();
        ConnectionEntry entry = registry.register(channel(), systemId("legacy1"));

        // The guard under mutation-test scrutiny (RED-on-neuter: neuter the CAS -> both calls return true).
        assertThat(entry.beginTearingDown()).isTrue();
        assertThat(entry.beginTearingDown()).isFalse();
        assertThat(entry.tearingDown()).isTrue();
    }

    @Test
    @DisplayName("RELAY-005: single-threaded double-teardown is idempotent — second leg no-ops, registry empty, attrs cleared")
    void beginTeardownIsIdempotentSingleThreaded() {
        ConnectionRegistry registry = new ConnectionRegistry();
        EmbeddedChannel ingress = channel();
        EmbeddedChannel egress = channel();
        registry.register(ingress, systemId("legacy1"));
        registry.attachEgress(ingress.id(), egress);

        ConnectionEntry first = registry.beginTeardown(ingress);

        assertThat(first).isNotNull();
        assertThat(registry.beginTeardown(ingress)).isNull(); // second ingress teardown — no-op
        assertThat(registry.beginTeardown(egress)).isNull();  // egress leg teardown — no-op
        assertThat(registry.size()).isZero();
        assertThat(registry.entryFor(ingress)).isNull();
        assertThat(registry.entryFor(egress)).isNull();
    }

    @Test
    @DisplayName("RELAY-005: teardown initiated from the EGRESS leg also removes the entry (channelInactive on either leg)")
    void beginTeardownFromEgressLegAlsoRemovesEntry() {
        ConnectionRegistry registry = new ConnectionRegistry();
        EmbeddedChannel ingress = channel();
        EmbeddedChannel egress = channel();
        registry.register(ingress, systemId("legacy1"));
        registry.attachEgress(ingress.id(), egress);

        ConnectionEntry winner = registry.beginTeardown(egress);

        assertThat(winner).isNotNull();
        assertThat(winner.ingressId()).isEqualTo(ingress.id());
        assertThat(registry.size()).isZero();
        assertThat(registry.entryFor(ingress)).isNull();
        assertThat(registry.entryFor(egress)).isNull();
    }

    @Test
    @DisplayName("RELAY-005: caller-side password double-zeroize is safe (the R8 relay slice)")
    void callerOwnedPasswordDoubleZeroizeIsSafe() {
        // The registry does not zeroize — the caller owns cred.password().zeroize() in finally (T7). RELAY-005
        // pins that re-entering the finally on a double-teardown is safe: a second wipe over an already-zeroed
        // backing array does not throw and leaves the array zeroed (Password.zeroize is idempotent).
        Password password = new Password(AsciiString.of("secret1"));
        AsciiString value = password.value();

        password.zeroize();
        password.zeroize(); // re-entrant — must not throw

        byte[] array = value.array();
        for (int i = value.arrayOffset(); i < value.arrayOffset() + value.length(); i++) {
            assertThat(array[i]).as("password backing byte %d is zero after double-zeroize", i).isEqualTo((byte) 0);
        }
    }

    @Test
    @DisplayName("RELAY-005: two-leg concurrent teardown — exactly one caller wins the race")
    void beginTeardownFromBothLegsExactlyOneWins() throws Exception {
        ConnectionRegistry registry = new ConnectionRegistry();
        EmbeddedChannel ingress = channel();
        EmbeddedChannel egress = channel();
        registry.register(ingress, systemId("legacy1"));
        registry.attachEgress(ingress.id(), egress);

        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<ConnectionEntry> fromIngress =
                    pool.submit(() -> {
                        start.await();
                        return registry.beginTeardown(ingress);
                    });
            Future<ConnectionEntry> fromEgress =
                    pool.submit(() -> {
                        start.await();
                        return registry.beginTeardown(egress);
                    });
            start.countDown();
            ConnectionEntry a = fromIngress.get(5, TimeUnit.SECONDS);
            ConnectionEntry b = fromEgress.get(5, TimeUnit.SECONDS);

            int winners = (a != null ? 1 : 0) + (b != null ? 1 : 0);
            assertThat(winners).as("exactly one leg wins the teardown race (the CAS-once guard)").isEqualTo(1);
        } finally {
            // MUST release the pool in finally — a neutered guard that strands a worker would hang the test JVM.
            pool.shutdownNow();
        }
        assertThat(registry.size()).isZero();
    }

    @Test
    @DisplayName("RELAY-006: egress-connect failure after an optimistic entry leaves no orphaned pair")
    void egressConnectFailureAfterEntryLeavesNoOrphan() {
        ConnectionRegistry registry = new ConnectionRegistry();
        EmbeddedChannel ingress = channel();
        // Optimistic creation: entry exists before the egress connect is attempted (egress never attached).
        ConnectionEntry entry = registry.register(ingress, systemId("legacy1"));
        assertThat(entry.egress()).isNull();
        assertThat(registry.size()).isEqualTo(1);

        // Egress-connect failed — the caller (T7 BindInterceptor) tears down the ingress leg it owns.
        ConnectionEntry removed = registry.beginTeardown(ingress);

        assertThat(removed).isSameAs(entry);
        assertThat(registry.size()).as("no orphaned entry lingers (a phantom pair corrupts AD-22 drain enumeration)").isZero();
        assertThat(registry.entryFor(ingress)).isNull();
        assertThat(registry.beginTeardown(ingress)).isNull(); // idempotent re-entry is still a no-op
    }
}
