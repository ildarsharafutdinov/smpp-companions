package smpp.companion.proxy.security;

import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 2.1 Task 2 — the <b>always-on</b> fail-closed mapping test for {@link RopcSlice} (AD-11) that needs no
 * live fixture and no in-process server, so the slice's collapse-to-{@link Verdict.DenyIndeterminate} on a
 * network error is never silently unverified (retro: no false-RESOLVED). The amended-contract arms — the D6
 * opaque-token deny and the D7 endpoint-verdict-alone allow — are pinned in {@link RopcSliceFailClosedTest}
 * against its in-process IdP; the slice's local-verify (kid-miss + claim-deny) rows were RETIRED with the arm
 * itself (Story 3.4 T8, 2026-08-29 — JWT signature verification, introspection, and mTLS client auth removed
 * from the test tier too).
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
                dead, KeycloakFixture.CLIENT_A_ID, KeycloakFixture.CLIENT_A_SECRET), 4)) {
            RequestContext rc = new RequestContext(
                    new SystemId(new AsciiString("testuser")), DefaultChannelId.newInstance(),
                    Instant.now().plusSeconds(8));
            VerdictRequest req = ScopedValue.where(CTX, rc).call(() -> slice.verify(cred(), CTX));
            Verdict v = req.future().get(20, TimeUnit.SECONDS);
            assertThat(v).isInstanceOf(Verdict.DenyIndeterminate.class);
        }
    }
}
