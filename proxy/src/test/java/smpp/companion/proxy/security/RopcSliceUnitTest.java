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
import java.util.function.Consumer;

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

    // ─────────────────────────────────────────────────────────────────────────────
    // Task 4 — AD-11 JWKS claim-deny branches (always-on, no fixture). Each bites a
    // distinct guard in RopcSlice.verifyWithJwks: a valid-kid JWT that fails the signature
    // check or an iss/aud/exp/nbf claim check collapses to DenyIndeterminate (fail-closed).
    // RED-on-neuter (AC9 / AI-1): drop the targeted guard in verifyWithJwks and the matching
    // test below goes RED. These cover the six deny branches the kid-miss test above does not.
    // ─────────────────────────────────────────────────────────────────────────────

    /** Full RSA key — signs the forged JWTs AND is the JWKS public key (kid "present") they resolve against. */
    private static final RSAKey SIGNING_KEY = newKey("present");
    /** A different key — a JWT signed by it has an unverifiable signature even with kid "present". */
    private static final RSAKey FORGE_KEY = newKey("forge");
    /** The JWKS the deny JWTs are verified against: only the public half of SIGNING_KEY. */
    private static final JWKSet JWKS = new JWKSet(SIGNING_KEY.toPublicJWK());

    private static RSAKey newKey(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException("could not generate RSA key", e);
        }
    }

    /** A slice whose verifyWithJwks issuer/audience are the fixture's (the only fields that path reads). */
    private static RopcSlice denySlice() {
        return new RopcSlice(HTTP, new RopcSlice.SliceConfig(
                KeycloakFixture.TOKEN_ENDPOINT, KeycloakFixture.INTROSPECTION_ENDPOINT, KeycloakFixture.JWKS_URI,
                KeycloakFixture.ISSUER, KeycloakFixture.CLIENT_A_ID, KeycloakFixture.CLIENT_A_SECRET, false, false), 4);
    }

    /** Signs a JWT with {@code key} + kid {@code kid} carrying exactly the claims {@code spec} adds (no defaults). */
    private static SignedJWT signJwt(RSAKey key, String kid, Consumer<JWTClaimsSet.Builder> spec) throws Exception {
        JWTClaimsSet.Builder b = new JWTClaimsSet.Builder();
        spec.accept(b);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(), b.build());
        jwt.sign(new RSASSASigner(key.toPrivateKey()));
        return jwt;
    }

    /** Signs + verifies a forged JWT against JWKS in one step, returning the collapsed Verdict. */
    private static Verdict verifyJwt(RSAKey key, String kid, Consumer<JWTClaimsSet.Builder> spec) throws Exception {
        return denySlice().verifyWithJwks(JWKS, signJwt(key, kid, spec).serialize());
    }

    @Test
    @DisplayName("JWKS: kid present but signature unverifiable (signed by a different key) → DenyIndeterminate (AD-11)")
    void jwksUnverifiableSignature_yieldsDenyIndeterminate() throws Exception {
        // kid "present" IS in the JWKS (passes kid lookup), but the JWT is signed by FORGE_KEY → signature verify fails.
        Verdict v = verifyJwt(FORGE_KEY, "present", b -> validClaims(b));
        assertThat(v).isInstanceOf(Verdict.DenyIndeterminate.class);
    }

    @Test
    @DisplayName("JWKS: issuer mismatch → DenyIndeterminate (AD-11)")
    void jwksIssuerMismatch_yieldsDenyIndeterminate() throws Exception {
        Verdict v = verifyJwt(SIGNING_KEY, "present", b -> validClaims(b).issuer("https://wrong-issuer"));
        assertThat(v).isInstanceOf(Verdict.DenyIndeterminate.class);
    }

    @Test
    @DisplayName("JWKS: audience mismatch → DenyIndeterminate (AD-11)")
    void jwksAudienceMismatch_yieldsDenyIndeterminate() throws Exception {
        Verdict v = verifyJwt(SIGNING_KEY, "present", b -> validClaims(b).audience("wrong-audience"));
        assertThat(v).isInstanceOf(Verdict.DenyIndeterminate.class);
    }

    @Test
    @DisplayName("JWKS: missing exp → DenyIndeterminate (AD-11)")
    void jwksMissingExpiry_yieldsDenyIndeterminate() throws Exception {
        Consumer<JWTClaimsSet.Builder> noExp = b -> b
                .issuer(KeycloakFixture.ISSUER)
                .audience(KeycloakFixture.CLIENT_A_ID);   // no expirationTime
        Verdict v = verifyJwt(SIGNING_KEY, "present", noExp);
        assertThat(v).isInstanceOf(Verdict.DenyIndeterminate.class);
    }

    @Test
    @DisplayName("JWKS: expired JWT → DenyIndeterminate (AD-11)")
    void jwksExpired_yieldsDenyIndeterminate() throws Exception {
        Verdict v = verifyJwt(SIGNING_KEY, "present", b -> validClaims(b)
                .expirationTime(Date.from(Instant.now().minusSeconds(600))));   // well past the 60s skew
        assertThat(v).isInstanceOf(Verdict.DenyIndeterminate.class);
    }

    @Test
    @DisplayName("JWKS: nbf in the future → DenyIndeterminate (AD-11)")
    void jwksNotBeforeFuture_yieldsDenyIndeterminate() throws Exception {
        Verdict v = verifyJwt(SIGNING_KEY, "present", b -> validClaims(b)
                .notBeforeTime(Date.from(Instant.now().plusSeconds(600))));   // nbf well past the 60s skew
        assertThat(v).isInstanceOf(Verdict.DenyIndeterminate.class);
    }

    @Test
    @DisplayName("JWKS: JWT with no kid header → DenyIndeterminate (AD-11; defense-in-depth w/ kid-miss)")
    void jwksMissingKidHeader_yieldsDenyIndeterminate() throws Exception {
        // No kid at all (not merely an absent kid) — a distinct malformed case. Behavior coverage: this guard is
        // defense-in-depth behind the kid-miss guard (a null kid reaches getKeyByKeyId(null) → null → DenyIndeterminate),
        // so it does not independently RED-on-neuter — but the AD-11 scenario is explicit here.
        SignedJWT noKid = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),   // no keyID
                validClaims(new JWTClaimsSet.Builder()).build());
        noKid.sign(new RSASSASigner(SIGNING_KEY.toPrivateKey()));
        assertThat(denySlice().verifyWithJwks(JWKS, noKid.serialize())).isInstanceOf(Verdict.DenyIndeterminate.class);
    }

    @Test
    @DisplayName("JWKS: malformed (unparseable) JWT → DenyIndeterminate (AD-11 fail-closed; defense-in-depth)")
    void malformedJwt_yieldsDenyIndeterminate() {
        // SignedJWT.parse throws on garbage → the catch-all in verifyWithJwks collapses to DenyIndeterminate.
        // Defense-in-depth behind adjudicate's catch; behavior coverage of the parse-failure path.
        assertThat(denySlice().verifyWithJwks(JWKS, "not-a-valid-jwt")).isInstanceOf(Verdict.DenyIndeterminate.class);
    }

    /** The valid claim set every deny case perturbs: correct issuer + audience + a non-expired exp. */
    private static JWTClaimsSet.Builder validClaims(JWTClaimsSet.Builder b) {
        return b.issuer(KeycloakFixture.ISSUER)
                .audience(KeycloakFixture.CLIENT_A_ID)
                .expirationTime(Date.from(Instant.now().plusSeconds(300)));
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
