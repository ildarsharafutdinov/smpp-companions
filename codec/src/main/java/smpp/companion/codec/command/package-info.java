/**
 * SMPP 3.4 {@code command_id} source of truth (AD-27, AD-3).
 *
 * <p>{@code SmppCommandIds.BIND_FAMILY} is the exhaustive set of {@code command_id}s the codec ever
 * parses into typed objects; every other {@code command_id} is opaque framed bytes.
 * {@code SmppCommandIds.MAX_COMMAND_LENGTH} is the AD-30 cap referenced by the framer (Story 1.2)
 * and — from Story 1.3 — by the relay direct-memory formula and the config default.
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.codec.command;

import org.jspecify.annotations.NullMarked;
