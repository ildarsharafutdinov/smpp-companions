package smpp.companion.proxy.config;

import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SEC-076 (VG1, landed with Story 5.2's review round) &mdash; the all-Paths scan the env-value
 * stance names as its LOAD-BEARING mechanism, now an actual test. The owner decisions of
 * 2026-09-11 ("env is accepted", no env-channel guard) close SEC-075/DEPLOY-008 on the
 * STRUCTURAL claim that a secret VALUE in the environment is inert because NO value key exists
 * to bind; this row is the machine check that keeps that claim true: it walks the whole
 * {@code companion.*} binding surface ({@link ProxyCompanionProperties} and every nested record)
 * and asserts every secret-MATERIAL key is a file-path key with no String value-key twin beside
 * it &mdash; a {@code client-secret} value field appearing beside {@code client-secret-path}
 * (the exact field an env var like {@code COMPANION_REVERSE_MODEB_OIDC_CLIENTSECRET} would
 * relaxed-bind) turns this RED.
 *
 * <p>"Path key" means the binding-level shape: the key's value is consumed exclusively as a
 * filesystem path ({@code CompanionConfigValidator.requireReadableFile} / the TLS factory) &mdash;
 * the material components are named and validated as paths, never carried as inline material.
 * Presence/shape only, deliberately: no behavior boot, no binding run (the matrix suites own
 * the validation behavior).
 *
 * <p><b>Carve-out, documented:</b> {@code TrustStore.password} is a ratified VALUE component
 * (the keystore-open password, optional by AD-13's {@code KeyStore.load} semantics) &mdash; an
 * existing owner-ratified exception, not an env-injection material key: it names no key/PEM
 * material and its sibling {@code .path} is the path key this row pins. Every other value-shaped
 * secret spelling on the surface is forbidden.
 */
@Tag("unit")
@Tag("sec")
@Tag("p2")
class CompanionSecretSurfaceIsAllPathsTest {

    /** The secret-material path keys the surface MUST carry — exactly this set, no more, no less. */
    private static final Set<String> EXPECTED_MATERIAL_KEYS = Set.of(
            "Oidc.clientSecretPath",
            "TrustStore.path",
            "ServerCert.certPath", "ServerCert.keyPath",
            "ClientCert.certPath", "ClientCert.keyPath");

    /** The one ratified VALUE component on the surface (see the class javadoc). */
    private static final String RATIFIED_VALUE_CARVE_OUT = "TrustStore.password";

    /**
     * Value-key spellings that must name NO component anywhere on the surface: each is the inline
     * twin of a material path key or a generic secret-value channel. The twin rule below forbids
     * a path key's immediate sibling ({@code clientSecretPath} forbids {@code clientSecret});
     * this blocklist catches the spellings landing on ANY record, not just beside their twin.
     */
    private static final Set<String> FORBIDDEN_VALUE_KEYS = Set.of(
            "clientSecret", "clientSecretValue", "clientCredential", "clientCredentialValue",
            "secret", "secretValue", "privateKey", "privateKeyValue",
            "cert", "certValue", "certificate", "keyValue",
            "keystore", "keystoreValue", "trustStoreValue", "password",
            "oidcClientSecret");

    @Test
    @DisplayName("SEC-076: every companion.* secret-material key is a file-path key — no String "
            + "value-key twin exists to bind (the structural mechanism behind the env-value stance)")
    void everySecretMaterialKeyIsAFilePathWithNoValueTwin() {
        Map<String, List<String>> componentsByRecord = new LinkedHashMap<>();
        collectRecordComponents(ProxyCompanionProperties.class, componentsByRecord);
        assertThat(componentsByRecord)
                .as("the walk reached the companion binding surface's records")
                .isNotEmpty();

        Set<String> materialKeys = new LinkedHashSet<>();
        for (Map.Entry<String, List<String>> record : componentsByRecord.entrySet()) {
            String recordName = record.getKey();
            List<String> names = record.getValue();
            materialKeys.addAll(materialComponents(recordName).stream()
                    .map(material -> recordName + "." + material)
                    .toList());

            // (1) the twin rule: a path key <X>Path must have NO value sibling <X> beside it —
            // an env var binds exactly such a sibling via relaxed binding; none may exist.
            for (String name : names) {
                if (name.endsWith("Path") && name.length() > "Path".length()) {
                    String base = name.substring(0, name.length() - "Path".length());
                    assertThat(names)
                            .as("the path key <%s.%s> carries a VALUE twin <%s> beside it — the "
                                    + "env-value stance's structural premise is broken (SEC-076)",
                                    recordName, name, base)
                            .doesNotContain(base);
                }
            }

            // (2) the blocklist: no forbidden value-key spelling anywhere on the surface, the
            // single ratified carve-out aside.
            for (String name : names) {
                if (RATIFIED_VALUE_CARVE_OUT.equals(recordName + "." + name)) {
                    continue;
                }
                assertThat(name)
                        .as("<%s.%s> is a forbidden secret-VALUE key on the companion surface "
                                + "(SEC-076: every material key is a file path; the sole ratified "
                                + "exception is TrustStore.password)", recordName, name)
                        .isNotIn(FORBIDDEN_VALUE_KEYS);
            }
        }

        // (3) the closed set: exactly the expected material path keys exist — a renamed/removed
        // path key REDs (the env stance silently lost its anchor), and a NEW material path key
        // REDs (an unlisted secret channel appeared; extend EXPECTED_MATERIAL_KEYS only by a
        // story that owns the new key).
        assertThat(materialKeys)
                .as("the surface's secret-material path-key set is exactly the expected one")
                .containsExactlyInAnyOrderElementsOf(EXPECTED_MATERIAL_KEYS);
    }

    /**
     * The components of the named record that carry secret MATERIAL as paths: the OIDC client
     * credential, the trust-store location, and every TLS cert/key. Named explicitly (not by
     * suffix-matching the whole surface) so a renamed key cannot silently drop out of the scan.
     */
    private static List<String> materialComponents(String recordName) {
        return switch (recordName) {
            case "Oidc" -> List.of("clientSecretPath");
            case "TrustStore" -> List.of("path");
            case "ServerCert", "ClientCert" -> List.of("certPath", "keyPath");
            default -> List.of();
        };
    }

    /**
     * Recursively collects every record component of the class tree, keyed by the record's simple
     * name — the {@code companion.*} binding surface, structurally enumerated (no Spring context).
     */
    private static void collectRecordComponents(Class<?> type, Map<String, List<String>> into) {
        for (Class<?> nested : type.getDeclaredClasses()) {
            collectRecordComponents(nested, into);
        }
        if (!type.isRecord()) {
            return;
        }
        List<String> names = new ArrayList<>();
        for (RecordComponent component : type.getRecordComponents()) {
            names.add(component.getName());
        }
        into.put(type.getSimpleName(), names);
    }
}
