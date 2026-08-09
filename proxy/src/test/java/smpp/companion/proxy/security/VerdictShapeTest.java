package smpp.companion.proxy.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC1 / AD-12: {@link Verdict} is the closed adjudication result that crosses the
 * {@code BindCredentialVerifier} port. Its SHAPE is the load-bearing invariant (the port is "immutable
 * henceforth" once Story 2.1 ratifies it), so this test pins the shape by reflection:
 *
 * <ul>
 *   <li>sealed — exactly three permits, no more can ever join;</li>
 *   <li>each permit is a payload-less record — <b>no {@code Throwable}, no free-form reason string,
 *       no Nimbus type</b> crosses the port (AD-12); the ROPC adapter absorbs the "why" — the port
 *       carries only allow/deny/deny-indeterminate.</li>
 * </ul>
 *
 * <p>RED-on-neuter (AC9 / AI-1): add a 4th permit, give a permit a component, or un-seal the interface and
 * this test fails.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-12 Verdict — sealed over three payload-less permits")
class VerdictShapeTest {

    @Test
    @DisplayName("Verdict is a sealed interface")
    void verdictIsSealedInterface() {
        assertThat(Verdict.class.isSealed())
                .as("Verdict must be sealed so no external subtype can extend the closed verdict set (AD-12)")
                .isTrue();
        assertThat(Verdict.class.isInterface()).isTrue();
    }

    @Test
    @DisplayName("Verdict permits exactly Allow, DenyInvalid, DenyIndeterminate — nothing else")
    void permitsExactlyTheThreeVerdicts() {
        var permits = Verdict.class.getPermittedSubclasses();
        assertThat(permits).as("sealed permits").isNotNull();
        var simpleNames = java.util.Arrays.stream(permits).map(Class::getSimpleName).toList();
        assertThat(simpleNames)
                .containsExactlyInAnyOrder("Allow", "DenyInvalid", "DenyIndeterminate");
        assertThat(permits).as("exactly three permits — no 4th verdict can ever cross the port").hasSize(3);
    }

    @Test
    @DisplayName("every permit is a payload-less record (no Throwable, no reason string, no Nimbus type)")
    void everyPermitIsPayloadLessRecord() {
        for (var permit : Verdict.class.getPermittedSubclasses()) {
            assertThat(permit.isRecord())
                    .as("%s must be a record", permit.getSimpleName()).isTrue();
            assertThat(permit.getRecordComponents())
                    .as("%s must carry ZERO components — no Throwable/reason/Nimbus type crosses the port (AD-12)",
                            permit.getSimpleName())
                    .isEmpty();
            assertThat(Verdict.class.isAssignableFrom(permit))
                    .as("%s must implement Verdict", permit.getSimpleName()).isTrue();
        }
    }

    @Test
    @DisplayName("every permit is final (records are final — cannot be further subclassed)")
    void everyPermitIsFinal() {
        // java.lang.Record subtypes are implicitly final; asserted so a future refactor to a non-record
        // 'class' permit cannot silently open the closed set.
        for (var permit : Verdict.class.getPermittedSubclasses()) {
            assertThat(java.lang.reflect.Modifier.isFinal(permit.getModifiers()))
                    .as("%s must be final", permit.getSimpleName())
                    .isTrue();
        }
    }
}
