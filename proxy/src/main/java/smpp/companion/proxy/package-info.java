/**
 * Root package of the smpp-companions proxy application — the {@code @SpringBootApplication}
 * entry point ({@link smpp.companion.proxy.ProxyCompanionApplication}). AD-16: NO embedded web
 * server; Netty is driven directly.
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy;

import org.jspecify.annotations.NullMarked;
