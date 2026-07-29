/**
 * SMPP 3.4 bind-family parsing (AC2; AD-3, AD-7, AD-12, AD-25, AD-27). The codec's single
 * parsed-vs-opaque boundary lives here: {@link smpp.companion.codec.bind.SmppCodec} consumes the
 * framed {@code ByteBuf} the framer emits and, for a {@link smpp.companion.codec.command.SmppCommandIds#BIND_FAMILY}
 * command_id ONLY, parses it into a typed {@link smpp.companion.codec.bind.SmppBindPdu}; every other
 * PDU flows through untouched as an opaque framed {@code ByteBuf} (AD-3/AD-32 — no TLV parser, no
 * non-bind body parser). The bind request is relayed to the SMSC byte-exact via the ORIGINAL framed
 * buffer (AD-12 — a security property), so the parser NEVER mutates its input (it reads header octets
 * with absolute gets and the body through a slice), and the typed object carries that retained original
 * as its forward unit (AD-2). The {@code ESME_ROK} predicate ({@link smpp.companion.codec.bind.SmppBindResponse#isOk()})
 * is the exact AD-25 signal the relay flips the splice on.
 *
 * <p>The parsed attack surface is exactly this one decoder (AD-24); every C-octet field — including the
 * password — is a Netty {@link io.netty.util.AsciiString} (lossless ASCII bytes). The password's backing
 * bytes are reachable for wiping via {@link io.netty.util.AsciiString#array()}, though the {@code toString()}
 * cache makes that seam fragile (user-directed, 2026-07-28 — overrides CODEC-024's {@code char[]}/{@code byte[]}
 * clause for full type-uniformity; see {@code SmppBindRequest} + the Dev Agent Record).
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.codec.bind;

import org.jspecify.annotations.NullMarked;
