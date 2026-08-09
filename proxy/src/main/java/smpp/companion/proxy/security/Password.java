package smpp.companion.proxy.security;

import io.netty.util.AsciiString;

import java.util.Arrays;
import java.util.Objects;

/**
 * The SMPP {@code password} as a typed value (AD-12). <b>Secret</b> — the ROPC credential validated against the IdP
 * token endpoint and zeroized on adjudication completion / connection teardown / exception (AC5 / AD-12); the typed
 * counterpart to the non-secret {@link SystemId} (AD-14).
 *
 * <p><b>Reinvention guardrail / type — {@link AsciiString} (CODEC-024/PRIV-1 revision, extended to the port
 * 2026-08-09):</b> the codec (Story 1.2, {@code SmppBindRequest}) already parses the password into a Netty
 * {@link AsciiString} — a user-directed 2026-07-28 override of the original {@code char[]}/{@code byte[]} clause "for
 * full type-uniformity" across every C-octet field; this type wraps that SAME backing (no conversion, no C-octet
 * re-parse at the port). The relay seam is {@code new Password(bindRequest.password())}. Enforces the SMPP 3.4
 * length bound (§3.2): the password C-octet string is max 9 octets incl. the NUL terminator (§3.1), so the value
 * carries at most {@value #MAX_LENGTH} value octets (the codec strips the terminator; it does not cap per-field
 * length — this is the typed-boundary fail-fast).
 *
 * <p><b>Zeroization — complete coverage via the shared backing array:</b> {@link AsciiString} is an immutable
 * {@link CharSequence}, so this record does <b>not</b> defensively copy it (mirroring {@link SystemId}; you would
 * not defensive-copy a {@link String}). {@link #value()} returns this same reference — that sharing is load-bearing:
 * because the holder and this record share one backing {@code byte[]} (reachable via {@link AsciiString#array()}),
 * the holder's single wipe covers this record's own copy too, closing the internal-copy zeroization gap a
 * {@code char[]} clone-on-read design could not. Centralized as {@link #zeroize()} (AC5 / AD-12) — the single
 * canonical wipe; callers must not re-implement the {@code AsciiString} array dance inline.
 *
 * <p><b>The hazard this accepts (CODEC-024 P2 / retro AI-5):</b> {@link AsciiString#toString()} lazily caches an
 * internal {@code String} — a single stray {@code toString()} on the password (a logger, a debugger watch, an
 * assert, an IDE evaluator) leaves an <b>immortal {@code String} copy that no backing-array wipe can reach</b>
 * ({@code new String(byte[])} allocates an independent array; {@link AsciiString#arrayChanged()} only nulls the
 * local reference). {@link #toString()} is overridden so this record itself never triggers it; the standing
 * CODEC-024 P2 "no {@code String} from the password octets" bytecode scan (retro AI-5, lands before relay logging)
 * must statically forbid {@code toString()} on the password across codec + port. Until it lands, the hazard is
 * documented, not mechanically enforced.
 *
 * @param value the {@code password} bytes EXCLUDING the wire NUL terminator the codec already stripped; non-null,
 *              &le; {@value #MAX_LENGTH} octets; never {@code toString()}ed.
 */
public record Password(AsciiString value) {

    /** SMPP 3.4 §3.2 {@code password}: max 9 octets incl. the NUL terminator &rarr; {@value} value octets. */
    public static final int MAX_LENGTH = 8;

    public Password {
        Objects.requireNonNull(value, "value");
        if (value.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "password is " + value.length() + " octets; exceeds the SMPP 3.4 max of " + MAX_LENGTH
                            + " value octets (9 incl. NUL terminator)");
        }
    }

    /**
     * Zeroize the backing {@code byte[]} (AC5 / AD-12) — the load-bearing secret-hygiene wipe and the single
     * canonical recipe (callers must not re-implement the {@link AsciiString} array dance inline). Because this
     * record shares the holder's backing array (no defensive copy — see class doc), the wipe covers every other
     * reference to the same {@link AsciiString}; {@link AsciiString#arrayChanged()} then drops its local {@code hash}
     * / cached-{@code toString} state. Idempotent.
     */
    public void zeroize() {
        Arrays.fill(value.array(), value.arrayOffset(), value.arrayOffset() + value.length(), (byte) 0);
        value.arrayChanged();
    }

    /**
     * Identified as a {@code Password} without rendering — or {@code toString()}-caching — the value. The record's
     * auto-generated {@code toString} would invoke {@link AsciiString#toString()}, rendering the cleartext AND
     * caching an immortal {@code String} the zeroization wipe cannot reach. This override is the value's single
     * most load-bearing secret-hygiene guard; the full no-String-from-password enforcement (CODEC-024 P2 / AI-5)
     * lands with relay logging.
     */
    @Override
    public String toString() {
        return "Password[***]";
    }
}
