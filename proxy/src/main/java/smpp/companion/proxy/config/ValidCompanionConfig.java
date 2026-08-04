package smpp.companion.proxy.config;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Class-level constraint (decision D4) on {@link ProxyCompanionProperties}. The role&times;mode cell is
 * encoded STRUCTURALLY in the property path ({@code companion.<role>.<mode>.*}), so this constraint
 * enforces: single-branch selection (exactly one of the five mode-leaves; AD-17 "one instance = one
 * role + one mode, mutually exclusive"); per-branch content checks &mdash; cert/key file readability
 * (SEC-056/057/060), routing non-empty + per-entry (SEC-058), OIDC https/present for forward
 * (SEC-053/054), SMSC host for reverse (SEC-059), trust-store 5-state PKIX load (SEC-050/096), Mode B
 * opt-in ack (SEC-052), forward+A no-SMSC positive (SEC-097); plus the unconditional TLS floor + cipher
 * intersection (AD-34/SEC-061) and the AD-30 finite-memory guard (RELAY-026 constant by construction).
 *
 * <p>forward&times;B is enforced structurally &mdash; no {@code companion.forward.mode-b} node exists
 * &mdash; so SEC-051 is retired from the runtime matrix. Field-level {@code @NotNull}/{@code @Min}/
 * {@code @Max} (cascaded via {@code @Valid} into the selected branch) handle per-field presence/range;
 * this constraint handles what they cannot express (single-branch selection + filesystem/content
 * checks). Fired by {@code @Validated} at bind time &rarr; non-zero startup exit on any violation
 * (AD-17). Mode B reverse+ack is the single non-refuse insecure posture: the validator returns valid
 * and the loud plaintext startup warning is emitted post-refresh by {@link CompanionModeBWarning}.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = CompanionConfigValidator.class)
public @interface ValidCompanionConfig {

    String message() default "companion.* configuration is invalid — refusing to start (AD-17).";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
