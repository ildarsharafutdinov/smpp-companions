package smpp.companion.proxy.security;

import java.util.Objects;

/**
 * The bind credential the {@link BindCredentialVerifier} adjudicates (AD-12): the SMPP identity ({@link SystemId})
 * and the SMPP password ({@link Password}). Composes the two typed values the relay seam builds from the codec's
 * parsed bind (CODEC-024/PRIV-1): {@code new BindCredential(new SystemId(bindRequest.systemId()),
 * new Password(bindRequest.password()))}.
 *
 * <p>Both components are immutable records holding a shared Netty {@code AsciiString} backing (no defensive copy —
 * see {@link SystemId} and {@link Password}); {@link BindCredential} adds no copy of its own. The password's
 * zeroization model and the {@code AsciiString.toString()}-cache hazard (CODEC-024 P2 / AI-5) are owned by
 * {@link Password}; this record's only secret-hygiene concern is its own {@link #toString()}.
 *
 * @param systemId the SMPP {@code system_id} (ROPC username / forwarded identity, AD-14); non-null.
 * @param password the SMPP {@code password} (ROPC credential, AD-12); non-null; secret — see {@link Password}.
 */
public record BindCredential(SystemId systemId, Password password) {

    public BindCredential {
        Objects.requireNonNull(systemId, "systemId");
        Objects.requireNonNull(password, "password");
    }

    /**
     * Identified as a {@code BindCredential} without rendering the password. Although {@link Password#toString()}
     * already redacts, this explicit override keeps the record's secret-hygiene contract self-contained (it does not
     * rely on {@link Password}'s override staying in place) and avoids the record's auto-{@code toString} touching
     * the password component at all. The full no-String-from-password enforcement (CODEC-024 P2 / AI-5) lands with
     * relay logging.
     */
    @Override
    public String toString() {
        return "BindCredential[systemId=" + systemId + ", password=***]";
    }
}
