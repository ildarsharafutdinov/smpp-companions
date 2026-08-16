package smpp.companion.proxy.relay;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * OBS-035/036/037 (Story 2.2 T9, AC6) &mdash; the A-1 ops-plan docs-falsifiability gate. A-1 (the
 * carrier multi-bind + DLR-affinity assumption) is <b>unfalsifiable in CI</b>: the in-JVM mock
 * EMULATES it and the jSMPP oracle approximates it. The only genuine falsification is the non-CI
 * real-carrier plan &mdash; and a plan that is vague is theatre. This gate scans
 * {@code docs/a-1-carrier-test-plan.md} (the repo-root docs surface; :proxy:test CWD = the proxy
 * module, docs is a sibling) for the three load-bearing shapes the TEA scenarios pin:
 *
 * <ul>
 *   <li><b>OBS-035 &mdash; an explicit, measurable PASS criterion:</b> a numeric concurrency bound
 *       ({@code 2 concurrent bind}) under the SAME {@code system_id}, both {@code ESME_ROK}, ON THE
 *       REAL CARRIER.</li>
 *   <li><b>OBS-036 &mdash; an explicit FAIL criterion + the DLR-affinity assertion:</b> a FAIL arm
 *       (2nd bind rejected by the carrier, OR a DLR on the wrong bind) and the concrete procedure
 *       ({@code submit_sm on bind A} &rarr; {@code deliver_sm} on bind A's socket, NOT bind B's).</li>
 *   <li><b>OBS-037 &mdash; the oracle is the real carrier (or a conformance SMSC), never the
 *       in-JVM mock:</b> the plan names the real target carrier as the system-under-oracle and
 *       EXPLICITLY excludes the in-JVM mock (which assumes A-1 and shares the codec's bugs).</li>
 * </ul>
 *
 * <p>Normalization: assertions run on the lowercased, whitespace-collapsed text so wording/markdown
 * tweaks do not false-RED; the asserted SHAPES (numeric bound, same-system_id, wrong-bind
 * language, mock exclusion) are the falsifiability content, not the prose. The doc file's existence
 * is asserted FIRST and loudly &mdash; a missing/renamed doc must fail the build, not silently
 * pass an empty scan (the T3 scan-root lesson). RED-on-neuter: blank the doc (or drop any of the
 * three sections) &rarr; the matching assertion goes RED.
 */
@Tag("integration")
@Tag("relay")
@Tag("p1")
@DisplayName("OBS-035/036/037 - the A-1 real-carrier ops plan is present and falsifiable (docs scan)")
class A1CarrierPlanDocsTest {

    /** The repo-root docs surface (sibling of the proxy module — the NoStringFromPasswordTest path idiom). */
    private static final Path PLAN = Path.of("../docs/a-1-carrier-test-plan.md");

    @Test
    @DisplayName("OBS-035: the plan defines an explicit measurable PASS criterion — ≥2 concurrent binds, "
            + "same system_id, both ESME_ROK, on the real carrier")
    void planDefinesExplicitPassCriterion() throws IOException {
        String plan = normalizedPlan();
        assertThat(plan)
                .as("OBS-035: a PASS criterion section must exist")
                .containsPattern(Pattern.compile("pass criterion"));
        assertThat(plan)
                .as("OBS-035: the concurrency bound must be NUMERIC (≥2 concurrent binds — 'several' is theatre)")
                .containsPattern(Pattern.compile("2 concurrent bind"));
        assertThat(plan)
                .as("OBS-035: the binds must be under the SAME system_id")
                .containsPattern(Pattern.compile("same system_id"));
        assertThat(plan)
                .as("OBS-035: the acceptance signal must be pinned to ESME_ROK")
                .containsPattern(Pattern.compile("esme_rok"));
        assertThat(plan)
                .as("OBS-035: the criterion must be scoped to the real carrier, not a lab mock")
                .containsPattern(Pattern.compile("on the real carrier"));
    }

    @Test
    @DisplayName("OBS-036: the plan defines an explicit FAIL criterion and the DLR-affinity assertion "
            + "(submit on bind A → deliver_sm on bind A's socket, not bind B's)")
    void planDefinesExplicitFailCriterionAndDlrAffinityAssertion() throws IOException {
        String plan = normalizedPlan();
        assertThat(plan)
                .as("OBS-036: a FAIL criterion section must exist")
                .containsPattern(Pattern.compile("fail criterion"));
        assertThat(plan)
                .as("OBS-036: the multi-bind-rejection FAIL arm must be explicit (2nd bind rejected by carrier)")
                .containsPattern(Pattern.compile("2nd.{0,40}bind.{0,60}reject"));
        assertThat(plan)
                .as("OBS-036: the affinity PROCEDURE must be concrete — submit on bind A")
                .containsPattern(Pattern.compile("submit.{0,3}on bind a"));
        assertThat(plan)
                .as("OBS-036: …deliver_sm observed on bind A's socket")
                .containsPattern(Pattern.compile("deliver_sm.{0,80}on bind a"));
        assertThat(plan)
                .as("OBS-036: …and NOT on bind B's (the cross-delivery arm that makes A-1 falsifiable)")
                .containsPattern(Pattern.compile("not on bind b"));
    }

    @Test
    @DisplayName("OBS-037: the plan's oracle is the real target carrier (or a conformance SMSC) and "
            + "explicitly EXCLUDES the in-JVM mock")
    void planNamesRealCarrierOracleAndExcludesInJvmMock() throws IOException {
        String plan = normalizedPlan();
        assertThat(plan)
                .as("OBS-037: the real target carrier must be named as the system-under-oracle")
                .containsPattern(Pattern.compile("real target carrier"));
        assertThat(plan)
                .as("OBS-037: a conformance SMSC must be named as the fallback oracle")
                .containsPattern(Pattern.compile("conformance sm"));
        assertThat(plan)
                .as("OBS-037: the in-JVM mock must be EXPLICITLY excluded (it assumes A-1 — the whole point)")
                .containsPattern(Pattern.compile("never the in-jvm mock"));
    }

    /** Loads the plan (loudly — a missing doc fails here, never a vacuous green) and normalizes it. */
    private static String normalizedPlan() throws IOException {
        assertThat(PLAN)
                .as("the A-1 real-carrier test plan must exist at docs/a-1-carrier-test-plan.md "
                        + "(OBS-035; a missing plan fails the build, not the checkpoint)")
                .isRegularFile();
        String raw = Files.readString(PLAN);
        assertThat(raw).as("the plan must be non-empty").isNotBlank();
        // Lowercase + strip markdown backticks + collapse whitespace: formatting tweaks must not
        // false-RED the gate — the asserted SHAPES are the falsifiability content, not the prose.
        return raw.toLowerCase().replace("`", " ").replaceAll("\\s+", " ");
    }
}
