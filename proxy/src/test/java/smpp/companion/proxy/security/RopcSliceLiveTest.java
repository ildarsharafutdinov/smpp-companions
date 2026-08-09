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
 * real Keycloak &ge;26.7.0 fixture across all four paths: <b>Allow</b> (JWT happy path), <b>Allow</b> (RFC 7662
 * introspection {@code active:true}), <b>Allow</b> (RFC 8705 mTLS provider auth, NO {@code client_secret}), and
 * <b>DenyInvalid</b> (fixture finding #6: 400 {@code invalid_grant} for bad user creds + 401 {@code invalid_client}
 * for a bad client secret — both map to {@link Verdict.DenyInvalid} per AD-11 "4xx &ne; 200 &rarr; DENY").
 *
 * <p>Each test drives the <b>actual {@link BindCredentialVerifier#verify} port</b> (AC1 shape) with the
 * {@link RequestContext} bound via {@link ScopedValue} (AC4 / AD-5) and awaits the {@link Verdict} on the slice's
 * bounded virtual-thread pool (AC6 / AD-28(4)). Gated by {@code @Testcontainers(disabledWithoutDocker = true)}:
 * these run and bite whenever Docker is present (the {@link KeycloakContainer} fixture is started by the test
 * JVM on a dynamic port) and skip cleanly with an explicit reason when Docker is absent (CI); the always-on
 * {@link RopcSliceUnitTest} enforces the fail-closed mapping without the container.
 */
@Tag("integration")
@Tag("security")
@Tag("p1")
@Testcontainers(disabledWithoutDocker = true)
@DisplayName("AD-12 RopcSlice — real-ROPC validation slice across all four AD-12 paths (live Keycloak ≥26.7.0)")
class RopcSliceLiveTest {

    /** The Testcontainers-managed Keycloak &ge;26.7.0 fixture (replaces the external docker-compose). */
    @Container
    static final KeycloakContainer KEYCLOAK = new KeycloakContainer();

    /** Shared mTLS client: trusts the fixture CA + presents the client cert on every call (AD-12/AD-29). */
    private static final HttpClient HTTP = KeycloakFixture.newHttpClient();

    /** The {@link RequestContext} handle the slice re-binds on its pool thread (AD-5). */
    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    private static BindCredential cred(String user, String pass) {
        return new BindCredential(new SystemId(new AsciiString(user)), new Password(new AsciiString(pass)));
    }

    private static RopcSlice slice(String clientId, String clientSecret, boolean mtls, boolean introspect) {
        return new RopcSlice(HTTP, new RopcSlice.SliceConfig(
                KeycloakFixture.TOKEN_ENDPOINT,
                KeycloakFixture.INTROSPECTION_ENDPOINT,
                KeycloakFixture.JWKS_URI,
                KeycloakFixture.ISSUER,
                clientId, clientSecret, mtls, introspect), 8);
    }

    /** Verifies via the port, binding the context in a scope (models real relay usage), awaiting the Verdict. */
    private static Verdict verify(RopcSlice slice, BindCredential credential) throws Exception {
        RequestContext rc = new RequestContext(
                credential.systemId(), DefaultChannelId.newInstance(), Instant.now().plusSeconds(15));
        VerdictRequest request = ScopedValue.where(CTX, rc).call(() -> slice.verify(credential, CTX));
        return request.future().get(20, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("path 1 — valid ROPC → 200 + JWT → local JWKS defense-in-depth verify → Allow")
    void path1_jwt_happyPath_yieldsAllow() throws Exception {
        try (RopcSlice slice = slice(KeycloakFixture.CLIENT_A_ID, KeycloakFixture.CLIENT_A_SECRET, false, false)) {
            Verdict v = verify(slice, cred(KeycloakFixture.TEST_USER, KeycloakFixture.TEST_PASS));
            assertThat(v).isEqualTo(new Verdict.Allow());
        }
    }

    @Test
    @DisplayName("path 2 — RFC 7662 introspection active:true → Allow")
    void path2_introspection_activeTrue_yieldsAllow() throws Exception {
        try (RopcSlice slice = slice(KeycloakFixture.CLIENT_A_ID, KeycloakFixture.CLIENT_A_SECRET, false, true)) {
            Verdict v = verify(slice, cred(KeycloakFixture.TEST_USER, KeycloakFixture.TEST_PASS));
            assertThat(v).isEqualTo(new Verdict.Allow());
        }
    }

    @Test
    @DisplayName("path 3 — RFC 8705 mTLS provider auth (client cert, NO client_secret) → 200 + JWT → Allow")
    void path3_mtls_providerAuth_noSecret_yieldsAllow() throws Exception {
        try (RopcSlice slice = slice(KeycloakFixture.CLIENT_B_ID, null, true, false)) {
            Verdict v = verify(slice, cred(KeycloakFixture.TEST_USER, KeycloakFixture.TEST_PASS));
            assertThat(v).isEqualTo(new Verdict.Allow());
        }
    }

    @Test
    @DisplayName("path 4a — invalid user creds → 400 invalid_grant → DenyInvalid (fixture finding #6)")
    void path4a_invalidUserPassword_yieldsDenyInvalid() throws Exception {
        try (RopcSlice slice = slice(KeycloakFixture.CLIENT_A_ID, KeycloakFixture.CLIENT_A_SECRET, false, false)) {
            Verdict v = verify(slice, cred(KeycloakFixture.TEST_USER, "WRONGPW"));
            assertThat(v).isInstanceOf(Verdict.DenyInvalid.class);
        }
    }

    @Test
    @DisplayName("path 4b — invalid client secret → 401 invalid_client → DenyInvalid (fixture finding #6)")
    void path4b_invalidClientSecret_yieldsDenyInvalid() throws Exception {
        try (RopcSlice slice = slice(KeycloakFixture.CLIENT_A_ID, "WRONG-SECRET", false, false)) {
            Verdict v = verify(slice, cred(KeycloakFixture.TEST_USER, KeycloakFixture.TEST_PASS));
            assertThat(v).isInstanceOf(Verdict.DenyInvalid.class);
        }
    }
}
