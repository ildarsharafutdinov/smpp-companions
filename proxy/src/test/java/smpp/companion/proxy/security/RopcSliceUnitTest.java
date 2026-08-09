package smpp.companion.proxy.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 2.1 Task 2 — the <b>always-on</b> fail-closed mapping tests for {@link RopcSlice} (AD-11). These need no
 * live fixture and run in every build, so the slice's collapse-to-{@link Verdict.DenyIndeterminate} on network
 * error and on a JWKS {@code kid} miss is never silently unverified (retro: no false-RESOLVED). The
 * {@code cancelHttp()} wire-abort (AC3) and the dedicated zeroization / saturation / RED-on-neuter mutation pass
 * are a later task; these cover the T2 per-path {@code DenyIndeterminate} assertions.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-12 RopcSlice — fail-closed mapping (always-on; no live fixture needed)")
class RopcSliceUnitTest {

    private static final HttpClient HTTP = KeycloakFixture.newHttpClient();
    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    private static BindCredential cred() {
        return new BindCredential(new SystemId(new AsciiString("testuser")), new Password(new AsciiString("pw")));
    }

    @Test
    @DisplayName("unreachable token endpoint (network error) → DenyIndeterminate (AD-11 fail-closed, via the port)")
    void unreachableTokenEndpoint_yieldsDenyIndeterminate() throws Exception {
        URI dead = URI.create("https://127.0.0.1:1/realms/x/protocol/openid-connect/token");
        try (RopcSlice slice = new RopcSlice(HTTP, new RopcSlice.SliceConfig(
                dead, dead, dead, "https://127.0.0.1:1/realms/x",
                KeycloakFixture.CLIENT_A_ID, KeycloakFixture.CLIENT_A_SECRET, false, false), 4)) {
            RequestContext rc = new RequestContext(
                    new SystemId(new AsciiString("testuser")), DefaultChannelId.newInstance(),
                    Instant.now().plusSeconds(8));
            VerdictRequest req = ScopedValue.where(CTX, rc).call(() -> slice.verify(cred(), CTX));
            Verdict v = req.future().get(20, TimeUnit.SECONDS);
            assertThat(v).isInstanceOf(Verdict.DenyIndeterminate.class);
        }
    }

    @Test
    @DisplayName("JWKS kid-miss (forged JWT, kid absent from JWKS) → DenyIndeterminate; matching kid → Allow (AD-11)")
    void jwksKidMiss_yieldsDenyIndeterminate_andMatchingKidAllows() throws Exception {
        RSAKey presentKey = new RSAKeyGenerator(2048).keyID("present").generate();
        RSAKey forgeKey = new RSAKeyGenerator(2048).keyID("absent").generate();
        JWKSet jwks = new JWKSet(presentKey);

        RopcSlice slice = new RopcSlice(HTTP, new RopcSlice.SliceConfig(
                KeycloakFixture.TOKEN_ENDPOINT, KeycloakFixture.INTROSPECTION_ENDPOINT, KeycloakFixture.JWKS_URI,
                KeycloakFixture.ISSUER, KeycloakFixture.CLIENT_A_ID, KeycloakFixture.CLIENT_A_SECRET, false, false), 4);

        // Forged JWT signed by a key whose kid is ABSENT from the JWKS → fail-closed DenyIndeterminate.
        SignedJWT forged = signJwt(forgeKey, "absent", KeycloakFixture.ISSUER, KeycloakFixture.CLIENT_A_ID);
        assertThat(slice.verifyWithJwks(jwks, forged.serialize())).isInstanceOf(Verdict.DenyIndeterminate.class);

        // Same JWT signed by the JWKS-present key → valid signature + claims → Allow.
        SignedJWT valid = signJwt(presentKey, "present", KeycloakFixture.ISSUER, KeycloakFixture.CLIENT_A_ID);
        assertThat(slice.verifyWithJwks(jwks, valid.serialize())).isEqualTo(new Verdict.Allow());
    }

    private static SignedJWT signJwt(RSAKey key, String kid, String issuer, String audience) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                new JWTClaimsSet.Builder()
                        .issuer(issuer)
                        .audience(audience)
                        .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                        .build());
        jwt.sign(new RSASSASigner(key.toPrivateKey()));
        return jwt;
    }
}
