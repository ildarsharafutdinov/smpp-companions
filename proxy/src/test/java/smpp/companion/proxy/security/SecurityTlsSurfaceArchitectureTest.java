package smpp.companion.proxy.security;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * SEC-090 tightened for Epic 3 (Story 3.2 T8 / AC10) — the sanctioned TLS surface of the <b>production</b>
 * security layer. In {@code security/} main, {@code javax.net.ssl} is sanctioned for JDK
 * {@link SSLContext}/{@link SSLParameters} use only: trust rides the JDK-default
 * {@code TrustManagerFactory} with PKIX defaults over the dedicated IdP store (AD-13/AD-26) — never
 * hand-rolled PKIX path building/validation, never a custom {@code X509TrustManager} implementation,
 * and never the {@code com.sun.net.httpserver} stack ({@code HttpsParameters} et al.), which is a
 * test-tier stand-in concern and must stay out of main.
 *
 * <p><b>Why this analyzes main classes only</b> ({@code DO_NOT_INCLUDE_TESTS}): the test tier legitimately
 * builds fixture HTTPS stand-ins ({@code OidcDiscoveryStandIn}, the in-process IdPs) on
 * {@code com.sun.net.httpserver} — the carve-out AC10 states explicitly. The forbid rules below would be
 * vacuously satisfiable if the layer silently stopped touching JDK TLS at all, so the class also carries the
 * <b>positive control</b>: the IdP TLS factory must actually depend on {@link SSLContext} <i>and</i>
 * {@link SSLParameters} — the sanctioned classes themselves. Unlike the forbid rules, a positive rule fails
 * when its selection matches nothing, which also makes a silent rename of the factory visible here.
 *
 * <p>RED-on-neuter (AI-1): plant an {@code X509TrustManager}-typed member, a {@code PKIXBuilderParameters}
 * reference, or an {@code HttpsParameters} import in any {@code security/} main class and the corresponding
 * rule fails.
 */
@AnalyzeClasses(packages = "smpp.companion.proxy", importOptions = ImportOption.DoNotIncludeTests.class)
class SecurityTlsSurfaceArchitectureTest {

    /**
     * SEC-090 / AD-13: no hand-rolled PKIX in {@code security/} main — chain building/validation stays inside
     * the JDK-default {@code TrustManagerFactory} algorithm; parameterizing it by hand is how "custom chain
     * validation" starts.
     */
    @ArchTest
    static final ArchRule securityMainMustNotHandRollPkix =
        noClasses()
            .that().resideInAPackage("..smpp.companion.proxy.security..")
            .should().dependOnClassesThat().belongToAnyOf(
                CertPathValidator.class, CertPathBuilder.class,
                PKIXParameters.class, PKIXBuilderParameters.class)
            .because("PKIX path building/validation is the JDK TrustManagerFactory's job with its defaults "
                    + "(AD-13: no custom chain-validation code, no PKIXBuilderParameters overrides) — "
                    + "hand-rolled PKIX is how trust-anchor bugs are born");

    /**
     * SEC-090 / AD-13: no custom trust-manager logic — depending on {@code X509TrustManager}/{@code TrustManager}
     * in {@code security/} main means implementing (or hand-wiring) one, i.e. replacing the JDK PKIX verdict with
     * our own. The factory's {@code TrustManagerFactory.getTrustManagers()} dispatch stays allowed: it produces
     * the JDK's own managers, it never names the interface.
     */
    @ArchTest
    static final ArchRule securityMainMustNotImplementCustomTrustLogic =
        noClasses()
            .that().resideInAPackage("..smpp.companion.proxy.security..")
            .should().dependOnClassesThat().belongToAnyOf(X509TrustManager.class, TrustManager.class)
            .because("peer-trust decisions must come from the JDK-default PKIX TrustManagerFactory over the "
                    + "dedicated IdP store (AD-13/AD-26) — a hand-written X509TrustManager is the classic "
                    + "accept-all/weak-validation regression and has no sanctioned use here");

    /**
     * SEC-090 / AC10: {@code com.sun.net.httpserver} ({@code HttpsServer}/{@code HttpsParameters}) is the
     * test-tier stand-in stack — it must never appear in production {@code security/} code.
     */
    @ArchTest
    static final ArchRule securityMainMustNotTouchSunHttpServer =
        noClasses()
            .that().resideInAPackage("..smpp.companion.proxy.security..")
            .should().dependOnClassesThat().resideInAPackage("com.sun.net.httpserver..")
            .because("com.sun.net.httpserver is the in-process stand-in IdP stack (test tier only); the "
                    + "provider-facing wire is java.net.http.HttpClient over the IdP SSLContext (AD-36) — "
                    + "HttpsParameters in main would mean the stand-in leaked into production");

    /**
     * SEC-090 / AC10 positive control: the IdP TLS factory really rides the sanctioned JDK classes — both
     * {@link SSLContext} and {@link SSLParameters} — so the forbid rules above guard a live surface, not an
     * empty one. Fails if the factory stops using either class or is renamed out of the rule.
     */
    @ArchTest
    static final ArchRule idpTlsFactoryRidesSanctionedJdkSslClasses =
        classes()
            .that().haveSimpleName(IdpSslContextFactory.class.getSimpleName())
            .should().dependOnClassesThat().haveFullyQualifiedName(SSLContext.class.getName())
            .andShould().dependOnClassesThat().haveFullyQualifiedName(SSLParameters.class.getName())
            .because("the sanctioned javax.net.ssl surface exists to be used exactly here: the factory builds the "
                    + "IdP SSLContext and derives the AD-34-intersected SSLParameters (SEC-090 tightening's "
                    + "positive control — forbids cannot be vacuous)");
}
