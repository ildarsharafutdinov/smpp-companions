package smpp.companion.proxy.security;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * SEC-090 / SEC-4 / AD-13 / AC7 — no hand-rolled crypto in the security layer, and the ROPC client uses only the
 * JDK builtin {@code java.net.http.HttpClient} + Nimbus. TLS goes through JDK {@code SSLEngine}/
 * {@code SSLContext}; provider-JSON parsing through Nimbus ({@code JSONObjectUtils}); HTTP through the JDK
 * client — never {@code sun.security..}, {@code javax.crypto..} ciphers/MACs, {@code java.security.MessageDigest},
 * a third-party HTTP client, or a non-Nimbus JSON/JWT library. Story 2.1 Task 5 extends the scaffold rule (which
 * only forbade {@code sun.security..}) with the {@code javax.crypto}/{@code MessageDigest} forbid, the
 * third-party-stack forbid, and the positive AC7 assertions that {@code RopcSlice} — the test-tier client that
 * ratifies the AD-12 port — uses the JDK {@code HttpClient} and Nimbus. Story 3.2 Task 8 (AC10) widens those
 * positive pins to the production adapter: {@code RopcBindCredentialVerifier} now rides the same two stacks
 * under the same rules — the condition is evaluated per class, so an adapter that drifts off the JDK client or
 * off Nimbus fails its row even while the slice stays compliant (the slice can ratify the contract, it cannot
 * mask the production tier). Story 3.4 T1+T2 (2026-08-27) removed local JWT verification from the production
 * adapter and T8 (2026-08-29) from the slice — Nimbus survives in BOTH tiers as the JSON parser alone (the
 * proxy carries no other JSON library); the JOSE/crypto surface is gone everywhere.
 */
@AnalyzeClasses(packages = "smpp.companion.proxy")
class NoRolledCryptoArchitectureTest {

    /** SEC-4 / AD-13: no hand-rolled crypto and no reach into JDK crypto internals from {@code security/}. */
    @ArchTest
    static final ArchRule securityLayerMustNotHandRollCryptoOrReachJdkInternals =
        noClasses()
            .that().resideInAPackage("..smpp.companion.proxy.security..")
            .should().dependOnClassesThat().resideInAnyPackage("sun.security..", "javax.crypto..")
            .orShould().dependOnClassesThat().haveFullyQualifiedName("java.security.MessageDigest")
            .because("TLS via JDK SSLEngine/SSLContext + provider JSON via Nimbus only — no hand-rolled ciphers/MACs/digests "
                    + "and no sun.security reach (SEC-4, AD-13). java.security.KeyStore/PKCS12 loading remains allowed; "
                    + "only MessageDigest (hand-rolled hashing) is forbidden.");

    /**
     * SEC-4 / AD-36: no third-party HTTP client or non-Nimbus JSON/JWT library admitted into {@code security/}. The
     * ROPC client speaks plain OIDC over {@code java.net.http.HttpClient} and parses provider JSON via Nimbus; a
     * vendor HTTP/JSON stack would re-couple the adapter to a specific IdP (the coupling AD-12 exists to localize)
     * and breach the AD-16/OBS-013 runtime-purity gate. Vacuously green today — a future-regression guard.
     */
    @ArchTest
    static final ArchRule securityLayerAdmitsNoThirdPartyHttpOrJwtStack =
        noClasses()
            .that().resideInAPackage("..smpp.companion.proxy.security..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "org.apache.http..", "okhttp3..", "com.squareup.okhttp..",
                    "org.springframework.web.client..", "org.springframework.web.reactive..",
                    "com.auth0..", "io.jsonwebtoken..", "org.bitbucket.jose4j..")
            .because("the ROPC client must use java.net.http.HttpClient + Nimbus only (AD-12/AD-36/SEC-4); "
                    + "no Keycloak SDK, no Apache/OkHttp, no Spring web client, no alternate JSON/JWT lib");

    /**
     * AC7 / AC10-T8: the ROPC wire rides the JDK builtin {@code HttpClient} — both {@code RopcSlice} (the test-tier
     * client that ratified the AD-12 port) and {@code RopcBindCredentialVerifier} (the production adapter behind it).
     * Referenced via {@code getSimpleName()} so a rename refactors the rule with the class.
     */
    @ArchTest
    static final ArchRule ropcClientsUseJdkHttpClient =
        classes()
            .that().haveSimpleName(RopcSlice.class.getSimpleName())
            .or().haveSimpleName(RopcBindCredentialVerifier.class.getSimpleName())
            .should().dependOnClassesThat().resideInAPackage("java.net.http..")
            .because("AC7 / AD-32 / AC5: the ROPC client must use java.net.http.HttpClient — the cancelHttp() wire "
                    + "abort and the raw-byte password/token hygiene depend on the JDK builtin client");

    /**
     * AC7 / AC10-T8: provider-JSON parsing goes through Nimbus (no hand-rolled JSON) — asserted of the test-tier
     * slice AND the production adapter, per class, for the same anti-masking reason as the HttpClient pin above.
     * (Amended role, Story 3.4 T8 2026-08-29: with local JWT verification gone from both tiers, this pin guards
     * the token/discovery-response JSON parse — the token itself is checked only structurally, library-free.)
     */
    @ArchTest
    static final ArchRule ropcClientsUseNimbus =
        classes()
            .that().haveSimpleName(RopcSlice.class.getSimpleName())
            .or().haveSimpleName(RopcBindCredentialVerifier.class.getSimpleName())
            .should().dependOnClassesThat().resideInAPackage("com.nimbusds..")
            .because("AC7 / SEC-4: provider-JSON parsing (discovery + token responses) must use Nimbus, never "
                    + "hand-rolled — the proxy carries no other JSON library (AD-36 amended role, Story 3.4 T1+T2+T8)");
}
