package smpp.companion.proxy.relay;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * AC1 / RELAY-025 / REL-4 / AD-8 / AD-9 &mdash; the structural statelessness invariant: the relay holds
 * socket-pairing state ONLY; a {@code message_id}&rarr;{@code system_id} (or {@code message_id}&rarr;channel)
 * correlation map <b>never exists</b> (that correlation is exactly what breaks the stateless / HA premise).
 * Behavioral coverage exists (RELAY-011: DLRs route via the coupled channel); this is the structural guard so
 * a future "performance cache" adding a {@code message_id}-keyed map cannot break REL-4 without failing this
 * scan. Mirrors the {@code Relay026ConstantContractTest} / {@code NoStringFromPasswordTest} source-scan idiom
 * (comment-strip then regex over CODE).
 *
 * <p>Two forbid-rules + one positive rule, scoped to {@code proxy/src/main/java/.../relay/}:
 * <ol>
 *   <li>no {@code message_id} / {@code messageId} identifier in CODE (the SMPP correlation key &mdash; it has
 *       no legitimate place in the state-ownership package);</li>
 *   <li>no {@link java.util.Map} (or {@code HashMap}/{@code ConcurrentHashMap}/{@code ConcurrentMap}/
 *       {@code NavigableMap}/{@code TreeMap}) keyed by {@code String}/{@code Long}/{@code Integer} &mdash; the
 *       {@code message_id} / sequence-number types. The ONE allowed map is the {@link ConnectionRegistry}'s
 *       {@code ChannelId}-keyed table, which this key type cannot match;</li>
 *   <li>positive: {@link ConnectionRegistry} declares a {@code ConcurrentHashMap<ChannelId} (the legit map is
 *       recognized, so dropping the registry cannot pass by silently failing the scan).</li>
 * </ol>
 *
 * <p><b>Honest scope:</b> this chases EXPLICIT keyed-by-String/Long/Integer maps + the {@code message_id}
 * identifier. A {@code Map<SomeDomainKey, SystemId>} using an opaque wrapper key is not caught by the
 * regex; it is caught by code review (and the behavioral RELAY-011). Same lighter-weight-than-AST trade-off
 * the other source-scans in this repo document. Comments are stripped so a doc mention of {@code message_id}
 * (AD-8/AD-9 cite it) is never a false offender.
 *
 * <p><b>RED-on-neuter (AC9 / AI-1):</b> inject a {@code private final Map<String, SystemId> messageIdIndex}
 * into any relay type and the forbid-rules go RED; delete the registry's {@code ChannelId}-keyed map and the
 * positive rule goes RED.
 */
@Tag("integration")
@Tag("relay")
@Tag("p1")
class Relay025StatelessnessScanTest {

    /** message_id / messageId identifier in CODE (camelCase or snake_case, word-boundaried). */
    private static final Pattern MESSAGE_ID_IDENTIFIER =
            Pattern.compile("\\bmessage_id\\b|\\bmessageId\\b");

    /**
     * Any Map-like type keyed by String / Long / Integer (the message_id / sequence-number key types). Matches
     * the simple-name forms the codebase uses (imports + unqualified). {@code ChannelId} cannot match.
     */
    private static final Pattern MESSAGE_ID_KEYED_MAP = Pattern.compile(
            "\\b(?:Map|HashMap|ConcurrentMap|ConcurrentHashMap|NavigableMap|TreeMap)<\\s*(?:String|Long|Integer)\\s*,");

    /** The legit map: the registry's ChannelId-keyed table (the recognized exception). */
    private static final Pattern CHANNELID_KEYED_REGISTRY_MAP =
            Pattern.compile("ConcurrentHashMap<\\s*ChannelId\\s*,");

    // Strip block comments (incl. javadoc) then line comments, so only CODE is scanned. The (?<!:) lookbehind
    // keeps "https://" (and other "://") protocol tokens from being treated as a line-comment start.
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("(?<!:)//[^\\n]*");

    /** The relay main source root (CWD of :proxy:test = the proxy module dir). */
    private static final Path RELAY_ROOT = Path.of("src/main/java/smpp/companion/proxy/relay");

    @Test
    @DisplayName("static: relay CODE has no message_id identifier and no message_id-keyed Map (REL-4 statelessness)")
    void relayHasNoMessageIdCorrelation() throws IOException {
        assertThat(Files.exists(RELAY_ROOT))
                .as("relay main source root must exist (test CWD = proxy module)").isTrue();

        List<String> identifierOffenders = new ArrayList<>();
        List<String> mapOffenders = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(RELAY_ROOT)) {
            for (Path file : walk.filter(p -> p.toString().endsWith(".java")).toList()) {
                String code = stripComments(Files.readString(file));
                String relative = RELAY_ROOT.relativize(file).toString();
                if (MESSAGE_ID_IDENTIFIER.matcher(code).find()) {
                    identifierOffenders.add(relative);
                }
                if (MESSAGE_ID_KEYED_MAP.matcher(code).find()) {
                    mapOffenders.add(relative);
                }
            }
        }
        assertThat(identifierOffenders)
                .as("no 'message_id'/'messageId' identifier in relay CODE (REL-4: socket-pairing state only)")
                .isEmpty();
        assertThat(mapOffenders)
                .as("no Map keyed by String/Long/Integer in relay CODE (the message_id correlation key; "
                        + "the only allowed map is the registry's ChannelId-keyed table)")
                .isEmpty();
    }

    @Test
    @DisplayName("static: ConnectionRegistry declares the legit ChannelId-keyed map (recognized exception)")
    void connectionRegistryDeclaresChannelIdKeyedMap() throws IOException {
        Path registry = RELAY_ROOT.resolve("ConnectionRegistry.java");
        assertThat(Files.exists(registry))
                .as("ConnectionRegistry.java must exist (the relay's one allowed Map owner)").isTrue();
        String code = stripComments(Files.readString(registry));
        Matcher m = CHANNELID_KEYED_REGISTRY_MAP.matcher(code);
        assertThat(m.find())
                .as("ConnectionRegistry keys its map by ChannelId (AD-8); dropping the registry must not pass "
                        + "by silently failing the scan")
                .isTrue();
    }

    private static String stripComments(String source) {
        return LINE_COMMENT.matcher(BLOCK_COMMENT.matcher(source).replaceAll(" ")).replaceAll(" ");
    }
}
