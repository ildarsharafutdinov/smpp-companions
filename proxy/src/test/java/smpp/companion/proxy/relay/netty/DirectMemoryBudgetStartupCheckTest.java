package smpp.companion.proxy.relay.netty;

import java.time.Duration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;

import io.netty.buffer.PooledByteBufAllocator;

import smpp.companion.proxy.ProxyCompanionApplication;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.testsupport.OidcDiscoveryStandIn;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AD-30 self-check at the Spring level &mdash; the {@link DirectMemoryBudgetStartupCheck} wired into the
 * full {@link ProxyCompanionApplication} context. Since Story 2.2 T5b the check is UNCONDITIONAL: every
 * role&times;mode cell carries it (proven here on a forward.mode-a boot, the cell Story 2.2 does not even
 * wire a relay for), and the over-budget severity follows {@code companion.memory.budget-check}:
 * {@code fail} (the default, incl. absent) refuses; {@code warn} emits the loud accepted-risk banner and
 * starts.
 *
 * <p>The fail cases bind {@code companion.memory.concurrent-pairs} to a value whose budget
 * (65536 × 64 × 1e6 × 1.5 ≈ 6.29 TB / 5.72 TiB) exceeds <em>any</em> realistic JVM direct-memory
 * ceiling &mdash; so the tests are deterministic regardless of the test JVM's
 * {@code -XX:MaxDirectMemorySize}/{@code -Xmx} (measured: the ceiling ranges from a few hundred MiB
 * under a capped CI JVM to several GiB on a dev box; a ~6.3 TB budget exceeds both). This is the
 * literal "bind {@code companion.memory.*} to values that exceed a deliberately-small live budget"
 * case &mdash; the live budget is the JVM's live direct-memory ceiling (explicit
 * {@code -XX:MaxDirectMemorySize}, else the {@code -Xmx} default), small relative to the huge budget.
 * (The null-vs-blank trap: the huge value is BOUND, not the key removed &mdash; removing
 * {@code companion.memory.*} trips the {@code @NotNull} guard first, hiding this check.)
 *
 * <p>The happy path binds a tiny budget (65536 bytes) that fits under any ceiling, proving the check
 * is wired and passes silently (no banner) for a provisioned relay, and that the AD-21 allocator bean
 * is the shared {@link PooledByteBufAllocator#DEFAULT}.
 */
@Tag("integration")
@Tag("relay")
@Tag("p1")
@ExtendWith(OutputCaptureExtension.class)
class DirectMemoryBudgetStartupCheckTest {

    /**
     * Story 2.2 T6: every VALID mode-b full-app boot now BINDS {@code companion.bind.port} (the relay
     * acceptor lifecycle). The three boots below that reach context refresh's lifecycle phase pass this
     * free port as a run-arg (HIGHEST precedence — beats application.yml's shipped 2775), so they never
     * collide with a locally-listening SMPP tool. The two refusal boots fail at refresh BEFORE the
     * lifecycle starts, so they need no port.
     */
    private static final int BIND_PORT = RelayTestFixtures.freePort();

    @Test
    @DisplayName("mode-b with a budget under the live ceiling starts silently, and the AD-21 allocator bean is the shared DEFAULT")
    void modeBWithSmallBudgetStartsAndSelfCheckPasses(@TempDir Path dir, CapturedOutput out) throws IOException {
        // Memory overrides are passed as command-line args to run(...) — HIGHEST precedence, so they beat
        // application.yml's companion.memory.* defaults (see modeBBuilder javadoc for why .properties() cannot).
        try (ConfigurableApplicationContext ctx = modeBBuilder(dir).run(
                "--companion.memory.max-inbound-depth=1",
                "--companion.memory.concurrent-pairs=1",
                "--companion.memory.safety-factor=1.0",
                "--companion.bind.port=" + BIND_PORT)) {
            assertThat(ctx.isActive()).isTrue();
            // The self-check bean exists → afterPropertiesSet ran and did not throw (budget 65536 < ceiling).
            assertThat(ctx.getBean(DirectMemoryBudgetStartupCheck.class)).isNotNull();
            // Pin the DEFAULT the FIXME established: application.yml (not code) carries budget-check: fail —
            // this full-app boot loads yml and does NOT override the key.
            assertThat(ctx.getBean(ProxyCompanionProperties.class).memory().budgetCheck())
                    .as("application.yml must ship companion.memory.budget-check=fail")
                    .isEqualTo(ProxyCompanionProperties.Memory.BudgetCheck.FAIL);
            // AD-21: the one shared pooled allocator bean is the canonical Netty singleton.
            assertThat(ctx.getBean(PooledByteBufAllocator.class))
                    .isSameAs(PooledByteBufAllocator.DEFAULT);
        }
        // Under-ceiling ⇒ NO accepted-risk banner (bites a broken comparison that would cry wolf).
        assertThat(out.getAll())
                .as("no over-budget banner for a budget under the ceiling")
                .doesNotContain("AD-30 DIRECT-MEMORY BUDGET");
    }

    @Test
    @DisplayName("mode-b with a budget exceeding the live ceiling refuses to start (AD-17 fail-fast, default policy)")
    void modeBBudgetExceedingLiveCeilingRefusesToStart(@TempDir Path dir, CapturedOutput out) throws IOException {
        // concurrent-pairs=1_000_000 → budget ≈ 6.29 TB / 5.72 TiB (a valid long; MemoryBudget.compute
        // does not overflow — 6.3e12 ≪ Long.MAX_VALUE), exceeding any realistic JVM direct-memory
        // ceiling. The huge value is BOUND as a command-line arg (not the memory key removed) — removing
        // the key trips the @NotNull guard first (null-vs-blank trap), hiding this check. budget-check is
        // deliberately NOT overridden here — note this bites application.yml's EXPLICIT `fail` (every
        // full-app boot loads yml); the absent/null⇒FAIL cell is bitten by the direct-construction unit
        // test below.
        assertThatThrownBy(() -> {
            ConfigurableApplicationContext ctx = modeBBuilder(dir).run("--companion.memory.concurrent-pairs=1000000");
            // RED-on-neuter exception-safety: if the guard was neutered the context STARTS instead of
            // throwing — close it so the unexpectedly-started context cannot outlive the assertion failure.
            ctx.close();
        }).hasRootCauseInstanceOf(DirectMemoryBudgetException.class);
        // FAIL path must refuse WITHOUT the accepted-risk banner — a hoisted println would tell the
        // operator the risk was "opted in" when it was not (review round 2, mutation-proven).
        assertThat(out.getAll())
                .as("no accepted-risk banner on the FAIL path")
                .doesNotContain("AD-30 DIRECT-MEMORY BUDGET");
    }

    @Test
    @DisplayName("forward.mode-a with a budget exceeding the live ceiling also refuses — the check is unconditional (T5b)")
    void forwardAWithHugeBudgetRefusesToStart(@TempDir Path dir, CapturedOutput out) throws IOException {
        // T5b removed the reverse.mode-b scoping: the check runs for EVERY role×mode cell. Proven on a
        // forward.mode-a full boot — a cell Story 2.2 wires no relay for (the budget still applies: every
        // cell relays, and Epic 3 must not have to remember to widen the guard). Same huge-budget +
        // RED-on-neuter discipline as the mode-b refusal (a reintroduced mode-b guard lets this context
        // START → the assertion fails and the context is closed).
        assertThatThrownBy(() -> {
            ConfigurableApplicationContext ctx = forwardABuilder(dir)
                    .run("--companion.memory.concurrent-pairs=1000000");
            ctx.close();
        }).hasRootCauseInstanceOf(DirectMemoryBudgetException.class);
        // (the F13 cap fits this boot's budget by construction: yml 1024 <= 1_000_000)
        assertThat(out.getAll())
                .as("no accepted-risk banner on the FAIL path")
                .doesNotContain("AD-30 DIRECT-MEMORY BUDGET");
    }

    @Test
    @DisplayName("budget-check=warn: an over-ceiling budget emits the loud accepted-risk banner and STARTS")
    void budgetCheckWarnOverCeilingStartsWithLoudBanner(@TempDir Path dir, CapturedOutput out) throws IOException {
        // Same over-ceiling budget as the refusal test, but the operator explicitly opted in:
        // no DirectMemoryBudgetException — the Mode-B-pattern banner on System.err (captured), then boot.
        // try-with-resources closes the context even if the banner assertion fails (RED-on-neuter
        // exception-safety — a neutered warn arm that still throws leaves nothing to close and fails RED).
        try (ConfigurableApplicationContext ctx = modeBBuilder(dir).run(
                "--companion.memory.concurrent-pairs=1000000",
                "--companion.memory.budget-check=warn",
                "--companion.bind.port=" + BIND_PORT)) {
            assertThat(ctx.isActive()).as("budget-check=warn: must start despite the over-ceiling budget").isTrue();
            assertThat(out.getAll())
                    .as("the loud over-budget accepted-risk banner must be emitted")
                    .contains("AD-30 DIRECT-MEMORY BUDGET")
                    .contains("budget-check=warn");
        }
    }

    @Test
    @DisplayName("budget-check=warn with a budget UNDER the ceiling starts with NO banner (bites the over-budget conjunct)")
    void budgetCheckWarnUnderCeilingStartsWithoutBanner(@TempDir Path dir, CapturedOutput out) throws IOException {
        // The (warn, under-ceiling) cell of the policy×budget matrix: warn ALONE must not banner — only
        // the over-budget trip does. Dropping the `budget > ceiling &&` conjunct would print the
        // ACCEPTED-RISK/"allocation can fail" banner on every adequately-provisioned warn boot; this test
        // goes RED under exactly that mutation (review round 2).
        try (ConfigurableApplicationContext ctx = modeBBuilder(dir).run(
                "--companion.memory.max-inbound-depth=1",
                "--companion.memory.concurrent-pairs=1",
                "--companion.memory.safety-factor=1.0",
                "--companion.memory.budget-check=warn",
                "--companion.bind.port=" + BIND_PORT)) {
            assertThat(ctx.isActive()).as("warn policy with an under-ceiling budget: must start").isTrue();
        }
        assertThat(out.getAll())
                .as("warn policy alone must not banner — only the over-budget trip does")
                .doesNotContain("AD-30 DIRECT-MEMORY BUDGET");
    }

    @Test
    @DisplayName("a non-WARN (defensively null) budget-check behaves as FAIL — over-ceiling budget refuses")
    void nullBudgetCheckBehavesAsFailOnOverCeilingBudget() {
        // Since the component became NON-null (owner FIXME: FAIL default ships in application.yml), null
        // is outside the record contract — but a yml-less bind can still deliver one, and the check's
        // `== WARN` comparison must stay null-safe fail-closed (any non-WARN ⇒ refuse). Pinned HERE, at
        // the enforcement site, on a directly-constructed record (no Spring; NullAway is main-only):
        // over-ceiling budget (64 × 1_000_000 × 1.5 ≈ 6.29 TB ≫ any ceiling) + null MUST throw.
        // RED under the `!= FAIL` mutation (null != FAIL would banner+boot instead of refusing).
        ProxyCompanionProperties props = new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(2775, "127.0.0.1", Duration.ofSeconds(4)),
                new ProxyCompanionProperties.Memory(64, 1_000_000, 1.5, null),
                new ProxyCompanionProperties.Tls(List.of("TLSv1.3"), List.of(), List.of()),
                null,
                new ProxyCompanionProperties.Reverse(
                        null,
                        new ProxyCompanionProperties.ReverseModeB(
                                new ProxyCompanionProperties.Smsc("smsc.example", 2775), true,
                                RelayTestFixtures.testOidc()),
                        null));
        assertThatThrownBy(() -> new DirectMemoryBudgetStartupCheck(props).afterPropertiesSet())
                .isInstanceOf(DirectMemoryBudgetException.class);
    }

    /**
     * A reverse.mode-b boot builder. The mode-b branch (SMSC endpoint + plaintext opt-in ack, SEC-052/059)
     * is supplied via {@code .properties()} as <em>default</em> properties (lowest precedence) — that is
     * fine because {@code application.yml} has every branch COMMENTED OUT, so these are the only source
     * for the branch and they bind cleanly (same pattern as {@code BootstrapLifecycleTest}). Story 3.2
     * (AD-12 amended 2026-08-18): reverse cells adjudicate — the oidc node is REQUIRED here too
     * (stand-in provider-url + fixture-CA IdP trust store + the three budget keys at the yml-template
     * defaults). The {@code companion.memory.*} overrides, by contrast, MUST beat
     * {@code application.yml}'s live memory defaults (max-inbound-depth=64, concurrent-pairs=1024,
     * safety-factor=1.5 → a ~6 GiB budget), so callers pass them as command-line args to
     * {@code run(...)} (highest precedence).
     */
    private static SpringApplicationBuilder modeBBuilder(Path dir) throws IOException {
        // NON-BLANK content (3.2 T7): this full boot constructs the ROPC adapter bean, which loads
        // the secret at startup — an empty file would refuse (SEC-060).
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "stand-in-client-secret\n");
        Path idpTrustStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        return new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "companion.reverse.mode-b.smsc.host=smsc.example",
                        "companion.reverse.mode-b.smsc.port=2775",
                        "companion.reverse.mode-b.acknowledged=true",
                        "companion.reverse.mode-b.oidc.provider-url=" + OidcDiscoveryStandIn.url(),
                        "companion.reverse.mode-b.oidc.client-id=smpp-client-confidential",
                        "companion.reverse.mode-b.oidc.client-secret-path=" + secret,
                        "companion.reverse.mode-b.oidc.trust-store.path=" + idpTrustStore,
                        "companion.reverse.mode-b.oidc.trust-store.password=" + RelayTestFixtures.IDP_STORE_PASSWORD,
                        "companion.reverse.mode-b.oidc.timeout=4s",
                        "companion.reverse.mode-b.oidc.max-in-flight=64");
    }

    /**
     * A forward.mode-a boot builder (mirrors {@code BootstrapLifecycleTest.builder}): empty temp files for
     * the cell-required secret paths (existence+readability is what validation checks; the cert/key
     * content is a runtime TLS concern, later Epic 3 tasks). NO oidc keys — the forward role is a
     * trusted-side relay (AD-12 amended 2026-08-18); the reverse role adjudicates.
     */
    private static SpringApplicationBuilder forwardABuilder(Path dir) throws IOException {
        // [B] re-shape (Story 3.3): the forward branch carries the DIAL material — the REAL committed
        // trust store (this full boot constructs SmppLegTlsFactory, which loads it eagerly). NO oidc
        // keys — the forward role is a trusted-side relay (AD-12 amended 2026-08-18).
        var legs = RelayTestFixtures.smppTlsLegs(dir);
        return new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "companion.forward.mode-a.trust-store.path=" + legs.trustStore(),
                        "companion.forward.mode-a.trust-store.password="
                                + RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD,
                        "companion.forward.mode-a.routing[0].system-id=carrierOne",
                        "companion.forward.mode-a.routing[0].host=reverse.internal",
                        "companion.forward.mode-a.routing[0].port=2776");
    }
}
