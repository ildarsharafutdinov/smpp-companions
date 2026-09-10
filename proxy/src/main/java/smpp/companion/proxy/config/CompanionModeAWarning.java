package smpp.companion.proxy.config;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Emits the loud Mode A one-way-TLS startup warning <em>after</em> successful configuration
 * validation — the exact {@link CompanionModeBWarning} pattern (a {@code @PostConstruct} on a bean
 * that injects the validated {@link ProxyCompanionProperties} fires only when context refresh
 * completes, so the warning never fires for a config refused by some other violation). The
 * pre-[B] AD-12 text promised this signal; the 2026-08-21 [B] sweep re-titled the register entry
 * (a submission oracle, not a harvest point) and this bean restores the dropped operator-facing
 * half (code review 2026-08-27, D1).
 *
 * <p>Detection is structural: the warning fires iff the selected branch is
 * {@code companion.reverse.mode-a} — the internet-leg TLS listener that PRESENTS a cert but never
 * validates the peer (one-way TLS; no trust store on that cell by design).
 *
 * <p>Since Story 5.1 (T3, the parked stream decision resolved) the banner rides the logback
 * stream as ONE WARN JSON line on the shipped LogstashEncoder — never {@code System.err} — so a
 * packaged boot keeps stdout pure JSON-lines and stderr carries no plain text.
 */
@Slf4j
@Component
public final class CompanionModeAWarning {

    /** The loud one-way-TLS startup warning for a reverse&times;A instance (accepted-risk register, [B] residual). */
    static final String MODE_A_WARNING = """
            ************************************************************
            * MODE A (one-way TLS) is ACTIVE on a REVERSE instance.
            * The reverse CANNOT authenticate the connecting forward
            * (one-way TLS presents a cert; it never validates peers).
            * ACL-isolate the listener (companion.bind.host) or use
            * Mode C mTLS. This is an ACCEPTED RISK (AD-12 register).
            ************************************************************""";

    private final ProxyCompanionProperties properties;

    public CompanionModeAWarning(ProxyCompanionProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void emitIfModeA() {
        ProxyCompanionProperties.Reverse reverse = properties.reverse();
        if (reverse == null) {
            return;
        }
        if (reverse.modeA() != null) {
            log.warn(MODE_A_WARNING);
        }
    }
}
