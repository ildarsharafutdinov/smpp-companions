/**
 * The SMPP-leg TLS runtime (Story 3.3, the ratified [B] topology): the per-cell Netty
 * {@link io.netty.handler.ssl.SslContext} factory for the internet leg — the REVERSE cells' TLS
 * listener (modes A/C, {@code clientAuth(REQUIRE)} in C) and the FORWARD cells' per-session client
 * dials (per {@code tls.contexts} override / instance default). JDK SSLEngine provider only (no
 * BouncyCastle, no tcnative), PKIX defaults via the JDK-default {@code TrustManagerFactory} (AD-13),
 * per-context AD-34 intersection at startup (empty on either axis refuses, D2), and AD-20
 * endpoint-identification explicit per dial target. Distinct from {@code security/} (the IdP link's
 * JDK {@code HttpClient} TLS) — this package owns the relay data plane's Netty leg material.
 */
package smpp.companion.proxy.tls;
