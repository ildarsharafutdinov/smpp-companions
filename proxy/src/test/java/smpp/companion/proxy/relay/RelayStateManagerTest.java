package smpp.companion.proxy.relay;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import io.netty.channel.DefaultChannelId;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;

import smpp.companion.proxy.security.Password;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Story 3.4 T6 / AC7 &mdash; the {@link RelayStateManager} contract: the SINGLE pair-lifecycle
 * transition policy over {@link ConnectionRegistry}'s storage (T3, owner checkpoint 2026-08-28). Pins
 * the sealed-decision mechanics (Won carries the hygienic entry; Lost means no-op), the ABSORBED
 * ADJUDICATION HYGIENE &mdash; {@code cancelHttp()} + zeroize run INSIDE {@code beginTeardown} BEFORE the
 * Won return, so the remove+mark &rarr; cancel+wipe half of the AD-32 ordering is single-sited and
 * structurally un-gettable-wrong &mdash; the settle arm (drop the handle, wipe, but never cancel a
 * settled adjudication), and the in-flight assert's new home on the registration path.
 *
 * <p>The end-to-end arms (retry-bind cancel, teardown-on-leg-death, the deny write after the decision)
 * stay pinned through the real pipelines by {@code BindInterceptorTest} /
 * {@code BindInterceptorForwardRoleTest} / the two relay-handler suites over {@code CoupledPairHarness};
 * this suite pins the manager's own decision surface. Unique {@link DefaultChannelId}s per channel (the
 * registry keys by ChannelId &mdash; the singleton-id trap).
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
class RelayStateManagerTest {

    /** A recording cancellation handle: counts {@code cancelHttp()} calls (the AD-32 teardown arm). */
    private static final class CountingVerdictRequest implements VerdictRequest {
        final AtomicInteger cancelHttpCalls = new AtomicInteger();

        @Override
        public CompletableFuture<Verdict> future() {
            return new CompletableFuture<>(); // never settles — the teardown arm is what this fake exercises
        }

        @Override
        public void cancelHttp() {
            cancelHttpCalls.incrementAndGet();
        }
    }

    private static SystemId systemId(String value) {
        return new SystemId(AsciiString.of(value));
    }

    @Test
    @DisplayName("beginTeardown returns Won with the hygiene ALREADY done — cancelHttp + zeroize ran before "
            + "the Won return; the pair is removed and both attrs cleared; a second call is Lost with no re-cancel")
    void beginTeardownPerformsTheHygieneBeforeWonThenLoses() {
        ConnectionRegistry registry = new ConnectionRegistry();
        RelayStateManager manager = new RelayStateManager(registry);
        EmbeddedChannel ingress = new EmbeddedChannel(DefaultChannelId.newInstance());
        EmbeddedChannel egress = new EmbeddedChannel(DefaultChannelId.newInstance());
        ConnectionEntry entry = manager.register(ingress, systemId("legacy1"));
        manager.attachEgress(ingress.id(), egress);
        CountingVerdictRequest pending = new CountingVerdictRequest();
        Password password = new Password(AsciiString.of("pw123456"));
        manager.beginAdjudication(entry, pending, password);

        RelayStateManager.Teardown outcome = manager.beginTeardown(ingress);

        assertThat(outcome).as("the first teardown caller wins the sealed decision").isInstanceOf(RelayStateManager.Teardown.Won.class);
        assertThat(((RelayStateManager.Teardown.Won) outcome).entry())
                .as("Won carries THE pair's entry for the caller's leg-specific tails")
                .isSameAs(entry);
        // The hygiene ran BEFORE the Won return (the caller's tails start from a hygienic pair):
        assertThat(pending.cancelHttpCalls).as("the in-flight ROPC is aborted inside the decision (AD-12/AD-32)").hasValue(1);
        assertThat(CoupledPairHarness.zeroized(password.value())).as("the pending password is wiped inside the decision (caller = the manager)").isTrue();
        assertThat(registry.size()).as("the pair left the registry (remove BEFORE close, AD-32)").isZero();
        assertThat(manager.entryFor(ingress)).as("both legs' cached attributes are cleared").isNull();
        assertThat(manager.entryFor(egress)).isNull();

        assertThat(manager.beginTeardown(egress))
                .as("a second teardown from the OTHER leg is Lost (RELAY-005 idempotence)")
                .isInstanceOf(RelayStateManager.Teardown.Lost.class);
        assertThat(pending.cancelHttpCalls).as("the settled-out handle was dropped — no double cancel").hasValue(1);
    }

    @Test
    @DisplayName("beginTeardown on a channel with no pair is Lost — the caller must no-op, never a close dance")
    void beginTeardownWithoutAPairIsLost() {
        RelayStateManager manager = new RelayStateManager(new ConnectionRegistry());

        assertThat(manager.beginTeardown(new EmbeddedChannel(DefaultChannelId.newInstance())))
                .isInstanceOf(RelayStateManager.Teardown.Lost.class);
    }

    @Test
    @DisplayName("settleAdjudication drops the handle and wipes the password but NEVER cancels — a settled "
            + "adjudication cannot be cancelled by a later teardown")
    void settleAdjudicationWipesWithoutCancelling() {
        RelayStateManager manager = new RelayStateManager(new ConnectionRegistry());
        EmbeddedChannel ingress = new EmbeddedChannel(DefaultChannelId.newInstance());
        ConnectionEntry entry = manager.register(ingress, systemId("legacy1"));
        CountingVerdictRequest pending = new CountingVerdictRequest();
        Password password = new Password(AsciiString.of("pw123456"));
        manager.beginAdjudication(entry, pending, password);

        manager.settleAdjudication(entry);

        assertThat(pending.cancelHttpCalls).as("settling is NOT cancelling — the adjudication completed").hasValue(0);
        assertThat(CoupledPairHarness.zeroized(password.value())).as("the caller-owned wipe runs on the settle path (every completion path)").isTrue();
        assertThat(manager.beginTeardown(ingress))
                .as("the later teardown still owns the pair removal (Won)")
                .isInstanceOf(RelayStateManager.Teardown.Won.class);
        assertThat(pending.cancelHttpCalls).as("the dropped handle is never cancelled post-settle").hasValue(0);
    }

    @Test
    @DisplayName("register refuses a channel that still carries a live pair — the in-flight assert's T6 home "
            + "(the registration path); a teardown arm that skipped the entry removal is a PATH BUG, not a race")
    void registerRefusesALivePairOnTheChannel() {
        RelayStateManager manager = new RelayStateManager(new ConnectionRegistry());
        EmbeddedChannel ingress = new EmbeddedChannel(DefaultChannelId.newInstance());
        manager.register(ingress, systemId("legacy1"));

        // Gradle test workers run with -ea, so the moved assert bites here exactly as it did at the
        // pre-T6 adjudicate head (BindInterceptor, owner FIXME 2026-08-15).
        assertThatThrownBy(() -> manager.register(ingress, systemId("legacy1")))
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("register reached with a live pair");
    }
}
