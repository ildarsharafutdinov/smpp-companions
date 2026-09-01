package smpp.companion.proxy.security;

import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.http.HttpClient;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 2.1 Task 2 / AC2 (load-bearing) — ratifies the AD-12 {@code proxy/security/} port contract against the
 * real Keycloak &ge;26.7.0 fixture in the <b>amended</b> 3-row shape (Story 3.4 T8, 2026-08-29 — the slice's
 * 2.1-era four-path historical ratification is ENDED: local JWT signature verification, RFC 7662 introspection,
 * and RFC 8705 mTLS client auth are removed from the test tier too, per the owner's 2026-08-29 direction; the
 * 2026-08-27 T1/T2 "deliberately UNCHANGED" dispositions and the 2026-08-19 mTLS precedent no longer shield
 * slice arms — the slice is now the LIVE ratification of the amended contract, mirroring the production
 * adapter): (1) ROPC with {@code client_secret} &rarr; 200 + JWT &rarr; the structural three-segment gate
 * &rarr; {@code Allow} on the endpoint verdict alone (no local verify — the D7 shape, pinned always-on in
 * {@link RopcSliceFailClosedTest}); (2a/2b) bad credentials &rarr; {@code DenyInvalid} both ways the fixture
 * exhibits them (400 {@code invalid_grant} &mdash; {@code path4a}; 401 {@code invalid_client} &mdash;
 * {@code path4b}; the historical 4-path row names are kept — chunk-B review 2026-09-01).
 *
 * <p>Each test drives the <b>actual {@link BindCredentialVerifier#verify} port</b> (AC1 shape) with the
 * {@link RequestContext} bound via {@link ScopedValue} (AC4 / AD-5) and awaits the {@link Verdict} on the slice's
 * bounded virtual-thread pool (AC6 / AD-28(4)). Gated by {@code @Testcontainers(disabledWithoutDocker = true)}:
 * these run and bite whenever Docker is present (the {@link KeycloakContainer} fixture is started by the test
 * JVM on a fixed port) and skip cleanly with an explicit reason when Docker is absent (CI); the always-on
 * {@link RopcSliceFailClosedTest} enforces the fail-closed mapping and the D6/D7 token arms without the container.
 */
@Tag("integration")
@Tag("security")
@Tag("p1")
@Testcontainers(disabledWithoutDocker = true)
@DisplayName("AD-12 RopcSlice — real-ROPC validation slice, amended contract (live Keycloak ≥26.7.0)")
class RopcSliceLiveTest {

    /** The Testcontainers-managed Keycloak &ge;26.7.0 fixture (replaces the external docker-compose). */
    @Container
    static final KeycloakContainer KEYCLOAK = new KeycloakContainer();

    /** Shared TLS client: trusts the fixture CA + presents the client cert on every call (transport identity). */
    private static final HttpClient HTTP = KeycloakFixture.newHttpClient();

    /** The {@link RequestContext} handle the slice re-binds on its pool thread (AD-5). */
    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    private static BindCredential cred(String user, String pass) {
        return new BindCredential(new SystemId(new AsciiString(user)), new Password(new AsciiString(pass)));
    }

    private static RopcSlice slice(String clientId, String clientSecret) {
        return new RopcSlice(HTTP, new RopcSlice.SliceConfig(
                KeycloakFixture.TOKEN_ENDPOINT, clientId, clientSecret), 8);
    }

    /** Verifies via the port, binding the context in a scope (models real relay usage), awaiting the Verdict. */
    private static Verdict verify(RopcSlice slice, BindCredential credential) throws Exception {
        RequestContext rc = new RequestContext(
                credential.systemId(), DefaultChannelId.newInstance(), Instant.now().plusSeconds(15));
        VerdictRequest request = ScopedValue.where(CTX, rc).call(() -> slice.verify(credential, CTX));
        return request.future().get(20, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("path 1 — valid ROPC (client_secret) → 200 + JWT → three-segment gate → Allow on the endpoint verdict alone")
    void path1_jwt_happyPath_yieldsAllow() throws Exception {
        try (RopcSlice slice = slice(KeycloakFixture.CLIENT_A_ID, KeycloakFixture.CLIENT_A_SECRET)) {
            Verdict v = verify(slice, cred(KeycloakFixture.TEST_USER, KeycloakFixture.TEST_PASS));
            assertThat(v).isEqualTo(new Verdict.Allow());
        }
    }

    @Test
    @DisplayName("path 4a — invalid user creds → 400 invalid_grant → DenyInvalid (fixture finding #6)")
    void path4a_invalidUserPassword_yieldsDenyInvalid() throws Exception {
        try (RopcSlice slice = slice(KeycloakFixture.CLIENT_A_ID, KeycloakFixture.CLIENT_A_SECRET)) {
            Verdict v = verify(slice, cred(KeycloakFixture.TEST_USER, "WRONGPW"));
            assertThat(v).isInstanceOf(Verdict.DenyInvalid.class);
        }
    }

    @Test
    @DisplayName("path 4b — invalid client secret → 401 invalid_client → DenyInvalid (fixture finding #6)")
    void path4b_invalidClientSecret_yieldsDenyInvalid() throws Exception {
        try (RopcSlice slice = slice(KeycloakFixture.CLIENT_A_ID, "WRONG-SECRET")) {
            Verdict v = verify(slice, cred(KeycloakFixture.TEST_USER, KeycloakFixture.TEST_PASS));
            assertThat(v).isInstanceOf(Verdict.DenyInvalid.class);
        }
    }
}
