package smpp.companion.proxy.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-024 P2 / AI-5 (AC9) — the "no {@code String} from the password octets" static gate. A single stray
 * {@code AsciiString.toString()} on the password (a logger, a debugger watch, an assert, an IDE evaluator) caches an
 * <b>immortal {@code String}</b> that the backing-array zeroization wipe ({@code Password.zeroize()}) cannot reach.
 * {@code Password}, {@code BindCredential}, and (as of Story 2.2 T3) {@code SmppBindRequest} override
 * {@code toString()} so the types themselves never trigger it; this scan keeps FUTURE code honest across the three
 * packages that touch the secret: {@code codec} (parses it), {@code proxy/security} (types it),
 * {@code proxy/relay} (forwards + zeroizes it).
 *
 * <p>Guard (mirrors {@code Relay026ConstantContractTest}'s source-scan pattern): walk the CODE (comments stripped, so
 * javadoc mentions like {@code AsciiString.toString()} never false-fire) of the three source roots and forbid an
 * explicit {@code .toString()} on any password-typed expression —
 * <ul>
 *   <li><b>Rule 1 — the {@code .password()} chain:</b> {@code req.password().toString()},
 *       {@code cred.password().value().toString()}, etc. (the raw {@link io.netty.util.AsciiString} the codec parses
 *       and the port wraps);</li>
 *   <li><b>Rule 2 — a {@code Password}-typed variable's {@code .value()}:</b> {@code Password p = ...;
 *       p.value().toString()} (the inner {@link io.netty.util.AsciiString} the record guards).</li>
 * </ul>
 * Plus a positive existence check: {@code SmppBindRequest} declares a {@code toString()} override — <b>drop that
 * override and this scan goes RED</b> (the subtask's named RED-on-neuter link); the matching golden-string assertion
 * lives in {@code Smpp.companion.codec.bind.SmppBindRequestTest} (codec).
 *
 * <p><b>Honest scope:</b> the scan catches EXPLICIT {@code .toString()} on the password (the documented auto-toString
 * leak vector and any direct call). It does NOT chase IMPLICIT String materialization (string concatenation,
 * {@code String.valueOf}, passing the raw {@code AsciiString} to a logger) — those are covered by the relay-logging
 * discipline rule (AC9: log {@code SystemId} only, never the {@code SmppBindRequest}/{@code Password}/
 * {@code BindCredential} objects nor the raw {@code password()} {@link io.netty.util.AsciiString}), recorded on
 * {@code SmppBindRequest.toString()}. (Same lighter-weight-than-AST trade-off
 * {@code Relay026ConstantContractTest} documents.) The source roots are asserted to exist so a path drift fails
 * loudly, not as a silent false-green.
 */
@Tag("integration")
@Tag("security")
@Tag("p1")
@DisplayName("CODEC-024 P2 / AI-5 - no String from the password octets (source scan)")
class NoStringFromPasswordTest {

    // The CWD of :proxy:test is the proxy module dir; codec is a sibling module (settings.gradle.kts: codec, proxy).
    private static final Path CODEC_MAIN = Path.of("../codec/src/main/java");
    private static final Path PROXY_MAIN = Path.of("src/main/java");
    private static final Path PROXY_SECURITY = PROXY_MAIN.resolve("smpp/companion/proxy/security");
    private static final Path PROXY_RELAY = PROXY_MAIN.resolve("smpp/companion/proxy/relay");
    private static final Path SMPP_BIND_REQUEST =
            CODEC_MAIN.resolve("smpp/companion/codec/bind/SmppBindRequest.java");

    // Rule 1: a .password() call (no-arg record/port accessor) chained — through zero or more .method(...) hops —
    // into a .toString(). Catches req.password().toString(), cred.password().value().toString(), etc.
    private static final Pattern PASSWORD_CHAIN_TO_STRING =
            Pattern.compile("\\.password\\(\\)\\s*(?:\\.\\w+\\([^)]*\\)\\s*)*\\.toString\\(\\s*\\)");
    // Rule 2: a Password-typed identifier declared in a file's CODE (Password <name>), whose <name>.value() chain we
    // then forbid from reaching .toString(). Excludes `new Password(` / `Password(` (no whitespace+ident follows).
    private static final Pattern PASSWORD_DECL = Pattern.compile("\\bPassword\\s+([a-zA-Z_$][\\w$]*)");
    // Override existence: SmppBindRequest declares a toString() (the RED-on-neuter link for the codec override).
    private static final Pattern TO_STRING_DECL = Pattern.compile("\\bString\\s+toString\\s*\\(\\s*\\)");

    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("(?<!:)//[^\\n]*");

    @Test
    @DisplayName("no .toString() on any password-typed expression across codec + proxy/security + proxy/relay")
    void noStringFromPassword() throws IOException {
        assertThat(Files.exists(CODEC_MAIN))
                .as("codec main source root must exist (test CWD = proxy module; codec is sibling)").isTrue();
        assertThat(Files.exists(PROXY_SECURITY))
                .as("proxy/security source root must exist").isTrue();

        List<String> offenders = new ArrayList<>();
        for (Path root : new Path[] {CODEC_MAIN, PROXY_SECURITY, PROXY_RELAY}) {
            if (!Files.exists(root)) {
                continue; // proxy/relay may be package-info-only or absent early; scanned once relay code lands.
            }
            try (Stream<Path> walk = Files.walk(root)) {
                for (Path file : walk.filter(p -> p.toString().endsWith(".java")).toList()) {
                    String code = stripComments(Files.readString(file));
                    collectPasswordChainOffenders(code, file, offenders);
                    collectPasswordVarValueOffenders(code, file, offenders);
                }
            }
        }
        assertThat(offenders)
                .as("no .toString() on a password-typed expression (.password() chain or Password-var .value()); "
                        + "the secret redacts to *** - see SmppBindRequest.toString()")
                .isEmpty();
    }

    @Test
    @DisplayName("SmppBindRequest declares a toString() override (RED-on-neuter: drop it -> this goes RED)")
    void smppBindRequestDeclaresToStringOverride() throws IOException {
        assertThat(Files.exists(SMPP_BIND_REQUEST))
                .as("SmppBindRequest source must exist at " + SMPP_BIND_REQUEST).isTrue();
        String code = stripComments(Files.readString(SMPP_BIND_REQUEST));
        assertThat(TO_STRING_DECL.matcher(code).find())
                .as("SmppBindRequest must declare a toString() override that redacts the password "
                        + "(CODEC-024 P2 / AI-5); drop it and the record's auto-toString leaks the password")
                .isTrue();
    }

    private static void collectPasswordChainOffenders(String code, Path file, List<String> offenders) {
        Matcher m = PASSWORD_CHAIN_TO_STRING.matcher(code);
        if (m.find()) {
            offenders.add(file + ": .password()...toString() - \"" + m.group().trim() + "\"");
        }
    }

    private static void collectPasswordVarValueOffenders(String code, Path file, List<String> offenders) {
        Set<String> passwordVars = new LinkedHashSet<>();
        Matcher decl = PASSWORD_DECL.matcher(code);
        while (decl.find()) {
            passwordVars.add(decl.group(1));
        }
        for (String name : passwordVars) {
            Pattern p = Pattern.compile(
                    "\\b" + Pattern.quote(name) + "\\s*\\.\\s*value\\(\\)\\s*(?:\\.\\w+\\([^)]*\\)\\s*)*\\.toString\\(\\s*\\)");
            Matcher m = p.matcher(code);
            if (m.find()) {
                offenders.add(file + ": " + name + ".value()...toString() - \"" + m.group().trim() + "\"");
            }
        }
    }

    private static String stripComments(String source) {
        return LINE_COMMENT.matcher(BLOCK_COMMENT.matcher(source).replaceAll(" ")).replaceAll(" ");
    }
}
