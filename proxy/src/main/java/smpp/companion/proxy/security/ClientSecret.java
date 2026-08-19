package smpp.companion.proxy.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * The OAuth {@code client_secret} as a typed, zeroizable value — the {@link Password} pattern applied
 * to the adapter's OWN secret material (AD-10(3): the OIDC client credential is one of the proxy's
 * runtime holdings). AD-18: the secret is a FILE PATH in config, read once at {@link #load} (adapter
 * construction), never an inline value. The holder owns the zeroization timing
 * ({@code RopcBindCredentialVerifier} wipes on {@code close()}); {@link #zeroize()} is the single
 * canonical wipe.
 *
 * <p>Record-over-array caveats, accepted deliberately: {@code equals}/{@code hashCode} are
 * identity-based (the array component) — correct here, since comparing secrets is never meaningful;
 * {@link #toString()} is overridden so the record never renders the value.
 */
@SuppressWarnings("ArrayRecordComponent") // reason: the byte[] component is load-bearing (raw access for
        // form encoding + zeroization); identity equals is the correct semantics for a secret. The
        // suppression keeps compileJava at zero warnings (house gate).
record ClientSecret(byte[] value) {

    ClientSecret {
        Objects.requireNonNull(value, "value");
    }

    /** Zeroize the backing array (AD-10) — the single canonical wipe; idempotent. */
    void zeroize() {
        Arrays.fill(value, (byte) 0);
    }

    /**
     * Identified as a {@code ClientSecret} without rendering the value (the {@link Password#toString()}
     * contract; the record's auto-generated {@code toString} would print the array reference and invite
     * a debugger to expand it).
     */
    @Override
    public String toString() {
        return "ClientSecret[***]";
    }

    /**
     * Loads the client secret from its AD-18 file path. Leading/trailing ASCII whitespace is trimmed
     * (secret files conventionally end with a newline — a stray {@code %0A} on the wire form would
     * silently corrupt the credential) and the raw read buffer is wiped so only the trimmed field
     * copy survives (AD-10). A missing/unreadable file and an empty (or whitespace-only) one refuse
     * startup with the SEC-060/AD-18 message convention.
     *
     * @param file       the {@code oidc.client-secret-path} file
     * @param configKey  the full config key the refusal message cites (e.g.
     *                   {@code companion.reverse.mode-b.oidc.client-secret-path})
     */
    static ClientSecret load(Path file, String configKey) {
        byte[] raw;
        try {
            raw = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new IllegalStateException(configKey + "=" + file
                    + " does not exist or is not readable — refusing to start (SEC-060/AD-18).", e);
        }
        int from = 0;
        int to = raw.length;
        while (from < to && isAsciiSpace(raw[from])) {
            from++;
        }
        while (to > from && isAsciiSpace(raw[to - 1])) {
            to--;
        }
        if (from == to) {
            throw new IllegalStateException(configKey + "=" + file
                    + " is empty (or whitespace only) — refusing to start (SEC-060/AD-18).");
        }
        byte[] secret = Arrays.copyOfRange(raw, from, to);
        Arrays.fill(raw, (byte) 0);
        return new ClientSecret(secret);
    }

    private static boolean isAsciiSpace(byte b) {
        return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f';
    }
}
