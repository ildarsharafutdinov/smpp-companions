package smpp.companion.proxy.bootstrap;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import smpp.companion.proxy.ProxyCompanionApplication;
import smpp.companion.proxy.config.TestCompanionConfigs;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.RelayStateManager;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.relay.netty.RelayIngressInitializer;
import smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 4.4 T5 (satellite c — the 2026-09-01 chunk-B ledger item): the <b>wiring-level same-bean
 * pin</b>. Spring singleton injection makes divergence unlikely, but AD-25's premise — the couple
 * unit ({@code RelayEgressHandler} on the egress leg) must resolve the SAME registry the ingress
 * arm's {@code BindInterceptor} wrote — was unpinned at the wiring level: the hand-built harnesses
 * share the pair by construction ({@code RelayTestFixtures.relayHarness}), the pipeline suite uses
 * deliberately DISJOINT pairs ({@code RelayPipelineInitializersTest}), and
 * {@code VerifierWiringConfigTest} covers the security wiring only. One full reverse-B boot closes
 * it: BOTH per-leg initializers carry the context's ONE {@link RelayStateManager} bean, and that
 * manager wraps the context's ONE {@link ConnectionRegistry} bean — the private final fields ARE
 * the wiring under test (no accessors exist), read with plain {@link java.lang.reflect.Field}
 * (no ReflectionTestUtils in this tier — dependency-light).
 *
 * <p><b>The positive control</b> (the forbid+positive-control idiom of
 * {@code RelayCoupleSiteArchitectureTest}, at the instance level): a second row hand-builds
 * initializers over DELIBERATELY DISJOINT managers and asserts the SAME comparison DOES
 * distinguish them ({@code isNotSameAs}) — the pin cannot be green by accident (a neutered field
 * read or a comparison that never discriminates goes RED there, not silently green here).
 *
 * <p>RED-on-neuter: compare the wiring row against a freshly-built manager instead of the context
 * bean (or drop the assertion) and the row goes RED; the class-level {@link Timeout} on a separate
 * thread bounds a pathological boot, never a stalled JVM.
 */
@Tag("integration")
@Tag("bootstrap")
@Tag("p1")
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@DisplayName("Story 4.4 T5 — relay wiring: the per-leg initializers share ONE manager/registry singleton")
class RelayWiringConfigTest {

    /** Per-invocation temp dir (the oidc secret + IdP trust-store fixture files live under it). */
    @TempDir
    Path dir;

    @Test
    @DisplayName("Story 4.4 T5 same-bean pin: one full reverse-B boot — BOTH initializers carry the "
            + "context's ONE RelayStateManager, and the manager wraps the context's ONE ConnectionRegistry "
            + "(AD-25's premise, pinned at the wiring level)")
    void bothLegInitializersShareTheOneManagerAndRegistryBeans() {
        // try-with-resources = the exception-safe close (the house rule): the idle close drives the
        // real AD-22 walk incl. the 4.4 T5 bounded quiesce — nothing to unwind by hand.
        try (ConfigurableApplicationContext ctx = reverseBBoot()) {
            assertThat(ctx.isActive()).as("the reverse-B cell must boot").isTrue();
            RelayStateManager managerBean = ctx.getBean(RelayStateManager.class);
            ConnectionRegistry registryBean = ctx.getBean(ConnectionRegistry.class);
            RelayIngressInitializer ingress = ctx.getBean(RelayIngressInitializer.class);
            RelayEgressInitializer egress = ctx.getBean(RelayEgressInitializer.class);
            assertThat(ctx.getBeansOfType(RelayStateManager.class))
                    .as("the premise's left half: exactly ONE manager bean in the context")
                    .hasSize(1);
            assertThat(ctx.getBeansOfType(ConnectionRegistry.class))
                    .as("exactly ONE registry bean in the context")
                    .hasSize(1);
            assertThat(field(ingress, "manager"))
                    .as("the INGRESS initializer's manager IS the context's single RelayStateManager "
                            + "(the BindInterceptor that registers pairs runs over this field)")
                    .isSameAs(managerBean);
            assertThat(field(egress, "manager"))
                    .as("the EGRESS initializer's manager IS the SAME bean (the couple unit resolves "
                            + "the registry the ingress arm wrote — AD-25)")
                    .isSameAs(managerBean);
            assertThat(field(managerBean, "registry"))
                    .as("the manager bean wraps the context's single ConnectionRegistry")
                    .isSameAs(registryBean);
        }
    }

    @Test
    @DisplayName("Story 4.4 T5 positive control: the same comparison DISTINGUISHES deliberately "
            + "disjoint managers — the pin cannot be green by accident (the forbid+positive-control idiom)")
    void theSameBeanComparisonDistinguishesDisjointManagers() {
        // The RelayPipelineInitializersTest disjoint-pairs shape: the harness's shared singleton
        // pair vs a hand-built manager over a FRESH registry — the same isSameAs/isNotSameAs read
        // the wiring row relies on must separate them.
        RelayTestFixtures.RelayHarness harness = RelayTestFixtures.relayHarness(
                RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1),
                new AlwaysAllowBindCredentialVerifier());
        RelayStateManager disjoint = new RelayStateManager(new ConnectionRegistry());
        RelayEgressInitializer egressOverDisjoint = new RelayEgressInitializer(disjoint, harness.observer());
        // No channels/loops to close — the initializers are inert until initChannel runs on a
        // channel, and the harness builds none.
        assertThat(field(harness.ingressInitializer(), "manager"))
                .as("the harness's ingress manager is the harness singleton")
                .isSameAs(harness.manager())
                .isNotSameAs(disjoint);
        assertThat(field(harness.egressInitializer(), "manager"))
                .as("the harness's egress manager is the SAME singleton (the sharing the wiring row pins)")
                .isSameAs(harness.manager())
                .isNotSameAs(field(egressOverDisjoint, "manager"));
        assertThat(field(egressOverDisjoint, "manager"))
                .as("a hand-built initializer over a DISJOINT manager reads as disjoint")
                .isSameAs(disjoint)
                .isNotSameAs(harness.manager());
    }

    /**
     * The lightest full cell — reverse-B (plaintext internet leg, no TLS listener material) over the
     * REAL component scan, so the initializers/manager/registry beans are the production wiring,
     * not a slice. Every common key rides as RUN args ({@code SpringApplicationBuilder.properties()}
     * LOSES to application.yml — args outrank it); {@link TestCompanionConfigs#reverseB(Path)}
     * states the whole common set itself (minimal 1/1/1.0 AD-30 budget, free bind/metrics ports,
     * the 4.4 T4 idle key), so the "--" mapping below is the whole boot configuration.
     */
    private ConfigurableApplicationContext reverseBBoot() {
        String[] args = Arrays.stream(TestCompanionConfigs.reverseB(dir).propertyValues())
                .map(property -> "--" + property)
                .toArray(String[]::new);
        return new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .run(args);
    }

    /**
     * Reads a private field with plain {@link java.lang.reflect.Field}: the initializers' manager
     * fields (and the manager's registry field) have no accessors — the private final wiring IS
     * the contract under test, and this tier keeps to JDK reflection (no ReflectionTestUtils).
     */
    private static Object field(Object bean, String name) {
        try {
            Field f = bean.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(bean);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                    "cannot read field '" + name + "' of " + bean.getClass().getName(), e);
        }
    }
}
