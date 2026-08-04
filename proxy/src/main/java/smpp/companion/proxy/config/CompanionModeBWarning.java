package smpp.companion.proxy.config;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

/**
 * Emits the AD-17 / SEC-052 loud plaintext Mode B startup warning <em>after</em> successful
 * configuration validation. A {@code @PostConstruct} on a bean that injects the validated
 * {@link ProxyCompanionProperties} fires only when context refresh completes &mdash; i.e. only for a
 * config that actually starts. This keeps the warning honest: it never fires for a reverse&times;B+ack
 * config that is then refused for some other field-level violation ({@code @NotNull}/{@code @Min}),
 * which an in-validator emission could not guarantee (the class-level constraint cannot see the
 * field-level failures Hibernate Validator evaluates in the same pass). The fail-fast matrix itself
 * stays the single validation mechanism (decision D4); this bean owns only the startup banner.
 *
 * <p>Detection is structural: the warning fires iff the selected branch is
 * {@code companion.reverse.mode-b} and it was acknowledged (which the validator already required to
 * start &mdash; so reaching {@code @PostConstruct} on that branch implies ack was true).
 */
@Component
public final class CompanionModeBWarning {

    /** The AD-31 / SEC-052 loud plaintext startup warning for an acknowledged Mode B reverse instance. */
    static final String MODE_B_WARNING = """
            ************************************************************
            * MODE B (plaintext) is ACTIVE on a REVERSE instance.
            * SMPP passwords transit the network in PLAINTEXT.
            * Mode B is opt-in and was acknowledged via
            * companion.reverse.mode-b.acknowledged=true.
            * Restrict the reverse<->SMSC leg; this is an accepted risk.
            ************************************************************""";

    private final ProxyCompanionProperties properties;

    public CompanionModeBWarning(ProxyCompanionProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void emitIfModeB() {
        ProxyCompanionProperties.Reverse reverse = properties.reverse();
        if (reverse == null) {
            return;
        }
        var modeB = reverse.modeB();
        if (modeB != null && modeB.acknowledged()) {
            System.err.println(MODE_B_WARNING);
        }
    }
}
