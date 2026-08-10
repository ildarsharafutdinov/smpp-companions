package smpp.companion.proxy.security;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * SEC-090 / SEC-4 / AD-13 / AC7 — no hand-rolled crypto in the security layer, and the ROPC client uses only the
 * JDK builtin {@code java.net.http.HttpClient} + Nimbus JOSE+JWT. TLS goes through JDK {@code SSLEngine}/
 * {@code SSLContext}; JWT/JWKS through Nimbus; HTTP through the JDK client — never {@code sun.security..},
 * {@code javax.crypto..} ciphers/MACs, {@code java.security.MessageDigest}, a third-party HTTP client, or a
 * non-Nimbus JWT library. Story 2.1 Task 5 extends the scaffold rule (which only forbade {@code sun.security..})
 * with the {@code javax.crypto}/{@code MessageDigest} forbid, the third-party-stack forbid, and the positive
 * AC7 assertions that {@code RopcSlice} — the test-tier client that ratifies the AD-12 port — uses the JDK
 * {@code HttpClient} and Nimbus.
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
            .because("TLS via JDK SSLEngine/SSLContext + JWT/JWKS via Nimbus only — no hand-rolled ciphers/MACs/digests "
                    + "and no sun.security reach (SEC-4, AD-13). java.security.KeyStore/PKCS12 loading remains allowed; "
                    + "only MessageDigest (hand-rolled hashing) is forbidden.");

    /**
     * SEC-4 / AD-36: no third-party HTTP client or non-Nimbus JWT library admitted into {@code security/}. The ROPC
     * client speaks plain OIDC over {@code java.net.http.HttpClient} and verifies JWTs via Nimbus; a vendor HTTP/JWT
     * stack would re-couple the adapter to a specific IdP (the coupling AD-12 exists to localize) and breach the
     * AD-16/OBS-013 runtime-purity gate. Vacuously green today — a future-regression guard.
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
                    + "no Keycloak SDK, no Apache/OkHttp, no Spring web client, no alternate JWT lib");

    /** AC7: the ROPC slice ratifies that the port's verifier uses the JDK builtin {@code HttpClient}. */
    @ArchTest
    static final ArchRule ropcSliceUsesJdkHttpClient =
        classes()
            .that().haveSimpleName("RopcSlice")
            .should().dependOnClassesThat().resideInAPackage("java.net.http..")
            .because("AC7 / AD-32 / AC5: the ROPC client must use java.net.http.HttpClient — the cancelHttp() wire "
                    + "abort and the raw-byte password/token hygiene depend on the JDK builtin client");

    /** AC7: the ROPC slice ratifies JWT/JWKS verification via Nimbus (no hand-rolled JWT). */
    @ArchTest
    static final ArchRule ropcSliceUsesNimbus =
        classes()
            .that().haveSimpleName("RopcSlice")
            .should().dependOnClassesThat().resideInAPackage("com.nimbusds..")
            .because("AC7 / SEC-4: JWT signature + JWKS + claim verification must use Nimbus JOSE+JWT, never hand-rolled");
}
