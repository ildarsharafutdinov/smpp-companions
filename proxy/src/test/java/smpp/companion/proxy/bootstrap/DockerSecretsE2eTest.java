package smpp.companion.proxy.bootstrap;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.model.ImageHistory;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Testcontainers;

import smpp.companion.proxy.testsupport.DockerRig;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Story 5.2 T4 &mdash; the Docker secrets E2E (DEP-1, FR-DEPLOY-4): the SAME rig as {@link
 * DockerImageBootSmokeTest} (the T2 distroless image over the one boot jar, the host-access
 * satellites, the cp'd {@link DockerContainerProbe}) proving the secrets contract end to end in
 * the container shape. The container rig itself lives in {@link DockerRig} ({@code testsupport/},
 * Story 6.2 T1 — the BH7 fold; this suite and {@code DockerImageBootSmokeTest} are the folded
 * consumers); this suite drives the rig's T4 knobs (container env, secret-file mount modes, the
 * stand-in IdP's form capture).
 *
 * <p><b>(a) DEPLOY-007 &mdash; mounted files, non-root UID, ready.</b> The cell boots with its two
 * secret files docker-cp'd to {@code /run/secrets} world-readable (the Design Note's arm: an
 * unprivileged test process cannot {@code chown} to UID 65532, so the readable-proof rides
 * group/world-readable modes &mdash; the LOAD-BEARING half is "the non-root JVM reads the mounted
 * file"). Readiness is the {@code startup_summary} line; the non-root proof is RUNTIME, not image
 * text: the container PID's {@code /proc/<pid>/status} pins {@code Uid/Gid 65532} on every field
 * (java is PID 1 via the exec-form ENTRYPOINT), and the probe's {@code readable} mode stats the
 * mounted files AS THE CONTAINER'S OWN UID ({@code docker exec} runs under the image user).
 *
 * <p><b>(b) DEPLOY-008 as amended (owner stance 2026-09-11: "env is accepted") &mdash; a secret
 * value in the container env is INERT, not refused.</b> No guard exists or lands: the AD-18
 * contract is upheld STRUCTURALLY (every secret key is a file Path, no value key exists to bind,
 * SEC-076's all-Paths scan is the mechanism). The row injects the decoy under BOTH relaxed-binding
 * spellings of the value key that would exist ({@code ...OIDC_CLIENTSECRET} &mdash; the name
 * Spring's binder WOULD resolve to a {@code client-secret} value field &mdash; and the underscored
 * decoy {@code ...OIDC_CLIENT_SECRET}), and asserts three things: the container still reaches
 * ready on the file-path secrets alone; the ONE wire place the client credential surfaces (the
 * ROPC token request's {@code client_secret} form field, captured by the stand-in IdP) carries the
 * MOUNTED FILE's value, never the decoy; and the decoy appears in NO stdout/log line. SEC-077's
 * Docker arm rides the correctly-configured run of row (a): {@code docker inspect} Env carries no
 * secret material at all &mdash; the value channel this row deliberately populates is the one
 * DEP-1 keeps empty by construction.
 *
 * <p><b>(c) DEPLOY-009 &mdash; missing file AND UID-unreadable file both refuse pre-bind.</b> Two
 * refused boots, one per bad state of the SAME configured path: the client-secret file absent
 * ({@code does not exist (OIDC client secret file missing)}), and present but mode 0600 under a
 * UID that is not 65532 ({@code is not readable (OIDC client secret file permissions)}). Both
 * exit non-zero with the {@code CompanionConfigValidator} refusal line (SEC-060/AD-18) on stdout
 * and reach NO {@code startup_summary} &mdash; the validation runs during the context refresh,
 * before the SMPP acceptor or the metrics listener can bind (no partial start).
 *
 * <p><b>(d) SEC-098 image-layer arm &mdash; no cert/key/secret material in ANY layer.</b> The
 * built image is {@code docker save}d and EVERY entry of the save (each layer blob/tar, the
 * config and manifest JSONs; blobs gunzipped when a daemon hands them over compressed) is
 * byte-scanned for the repo's actual secret material: the exact bytes of every committed fixture
 * cert/key/keystore under {@code keycloak/certs/} plus the rig's secret values. Two scan-design
 * findings (empirical, 2026-09-12): generic PEM markers are NOT scanned &mdash; the jlink
 * runtime's own {@code lib/modules} carries the JDK's internal {@code
 * -----BEGIN CERTIFICATE-----} constants, so a marker scan would false-positive on legitimate
 * runtime bytes &mdash; and markers only bite on files stored VERBATIM by COPY (the bake
 * scenario this row pins); {@code proxy.jar}'s own entries are zip-deflated inside the jar, so
 * plaintext inside the jar archive is invisible to a layer scan (mutation M3 finding). {@code
 * docker history} pins the payload surface: exactly the two COPY layers (runtime + jar), nothing
 * else baked.
 *
 * <p>Same rig constraints as T3: the image is a TEST INPUT built from the SAME assembled context
 * ({@code :proxy:assembleDockerContext} &mdash; its Gradle test-input wiring covers this suite
 * too); {@code disabledWithoutDocker} keeps daemon-less builds GREEN; class-level {@link Timeout}
 * on a separate thread (a stuck container FAILS the row, never hangs the suite) and {@link
 * DockerRig#close()} is exception-safe and idempotent.
 */
@Tag("integration")
@Tag("deploy")
@Tag("p1")
@Timeout(value = 600, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@Testcontainers(disabledWithoutDocker = true)
@DisplayName("Story 5.2 T4 — Docker secrets E2E (DEP-1): /run/secrets mounted under the non-root "
        + "UID, env-value secrets inert, bad secret files refuse pre-bind, no secret material in "
        + "any image layer")
class DockerSecretsE2eTest {

    /**
     * The image this suite builds and boots &mdash; the SAME three-entry context {@code
     * :proxy:dockerImage} assembles (one image definition with T3's suite; own tag so each suite's
     * reaper-tagged lifecycle stays its own). {@code ImageFromDockerfile} resolves lazily, once
     * per test JVM.
     */
    private static final ImageFromDockerfile IMAGE = DockerRig.suiteImage("smpp-proxy:t4-suite");

    /** The DEP-1 mount point: the only secret channel the container shape honors. */
    private static final String SECRETS_DIR = "/run/secrets";

    private static final String CLIENT_SECRET_PATH = SECRETS_DIR + "/oidc-client-secret";

    private static final String TRUST_STORE_PATH = SECRETS_DIR + "/idp-truststore.p12";

    /**
     * The mounted client-secret FILE's value — the credential the row proves is honored (the
     * folded rig's own mount value, aliased so the rows keep their name for it).
     */
    private static final String FILE_SECRET_VALUE = DockerRig.MOUNTED_CLIENT_SECRET_VALUE;

    /**
     * The container-env decoy value — secret MATERIAL deliberately injected through the channel
     * DEP-1 forbids, under both relaxed-binding spellings of the value key (row (b)'s premise).
     */
    private static final String ENV_DECOY_VALUE = "env-injected-decoy-secret";

    /** The distroless {@code nonroot} UID/GID (base-debian12:nonroot, fixed at 65532). */
    private static final String NONROOT_UID = "65532";

    // ── the pinned stdout markers (identical literals to the T3/JAR-shape smokes) ────────────────

    private static final String STARTUP_SUMMARY_MARKER = DockerRig.STARTUP_SUMMARY_MARKER;

    /**
     * The committed fixture PKI directory ({@code src/test/resources/keycloak/certs/}) &mdash;
     * walked by row (d)'s completeness check against {@link #FIXTURE_MATERIAL}.
     */
    private static final Path FIXTURE_CERTS_DIR = Path.of("src", "test", "resources", "keycloak", "certs");

    /**
     * The committed fixture PKI ({@code keycloak/certs/}, {@code generate.sh}) &mdash; every
     * cert/key/keystore file, whose EXACT BYTES are the layer-scan markers (row (d)). {@code
     * generate.sh} itself and the CA certs' .pem twins are covered by their p12/PEM bytes; the
     * list is the directory's closed set of material files, PINNED by row (d)'s completeness
     * assertion (a new fixture file must join the scan; a deleted one must leave it &mdash; a
     * hand-maintained list with no check would let the scan silently narrow).
     */
    private static final List<String> FIXTURE_MATERIAL = List.of(
            "ca-key.pem", "ca.pem",
            "client-key.pem", "client-keystore.p12", "client.pem",
            "docker-host-key.pem", "docker-host.pem",
            "foreign-ca-key.pem", "foreign-ca.pem",
            "keycloak-truststore.pem",
            "server-key.pem", "server.pem",
            "smpp-foreign-client-key.pem", "smpp-foreign-client.pem",
            "smpp-forward-client-key.pem", "smpp-forward-client.pem",
            "smpp-reverse-server-key.pem", "smpp-reverse-server.pem",
            "smpp-truststore.p12", "truststore.p12");

    /** The runtime secret VALUES the rigs mount (never legitimate image content). */
    private static final List<String> RUNTIME_SECRET_VALUES = List.of(
            FILE_SECRET_VALUE, "smpp-confidential-secret");

    /** Per-invocation temp dir (the mounted secret material and the docker-save spill). */
    @TempDir
    Path dir;

    // ── row (a): DEPLOY-007 + SEC-077's Docker arm ───────────────────────────────────────────────

    @Test
    @DisplayName("mounted /run/secrets reach ready under the non-root UID (DEPLOY-007): the "
            + "container's java runs as 65532 (live /proc proof), the UID reads both mounted "
            + "files (in-container stat as that UID), and a correctly-configured run's docker "
            + "inspect Env carries no secret material at all (SEC-077 Docker arm)")
    void mountedSecretsReachReadyUnderTheNonRootUid() throws Exception {
        try (DockerRig rig = DockerRig.launchReverseBCell(
                IMAGE, dir, "docker-secrets-idp", Map.of(), true, "r--r--r--", null)) {
            rig.awaitStartupSummary();

            // (1) The runtime UID/GID, from the LIVE process (not the image text): docker inspect's
            // State.Pid is the container's PID-1 java as seen by the HOST kernel; its /proc status
            // pins every UID/GID field to the distroless nonroot 65532.
            long pid = rig.container().getContainerInfo().getState().getPidLong();
            assertThat(pid)
                    .as("docker exposes the container's host PID (local daemon — this suite's "
                            + "platform, the PackagedBootSmokeTest /proc stance)")
                    .isPositive();
            String status = readProcStatus(pid);
            String expectedIds = (NONROOT_UID + " ").repeat(4).strip();
            assertThat(procIdLine(status, "Uid:"))
                    .as("PID 1 (java, exec-form ENTRYPOINT) runs as the non-root UID on every "
                            + "field: real, effective, saved, fs")
                    .isEqualTo(expectedIds);
            assertThat(procIdLine(status, "Gid:"))
                    .as("the non-root GID contract rides the same proof (DEPLOY-007: UID/GID)")
                    .isEqualTo(expectedIds);

            // (2) The load-bearing half of the Design Note: the non-root JVM READS the mounted
            // files. docker exec runs the image's own java under the container's user (65532), and
            // the probe stats the paths as that UID — mode 0444 exactly as the rig mounted them
            // (the docker-cp mode preservation the (c) unreadable arm turns into a refusal).
            for (String secret : List.of(CLIENT_SECRET_PATH, TRUST_STORE_PATH)) {
                Container.ExecResult stat = rig.execProbe("readable", secret);
                assertThat(stat.getExitCode())
                        .as("the container's own UID reads <%s> — stderr: <%s>", secret,
                                stat.getStderr())
                        .isZero();
                assertThat(stat.getStdout())
                        .as("the mounted mode rode the docker cp verbatim (world-readable, "
                                + "no write bit)")
                        .contains("readable " + secret, "perms=r--r--r--");
            }

            // (3) SEC-077's Docker arm on THIS correctly-configured run: docker inspect's Env
            // carries no secret material — only the base image's own variables. The value channel
            // row (b) deliberately populates is empty here BY CONSTRUCTION (paths ride args, the
            // only secret carrier is the mount).
            String[] env = rig.container().getContainerInfo().getConfig().getEnv();
            assertThat(env)
                    .as("the run carries an inspectable env (base-image variables at minimum)")
                    .isNotNull()
                    .isNotEmpty();
            for (String entry : env) {
                assertThat(entry)
                        .as("no env entry carries the mounted secret's VALUE (DEP-1: the env "
                                + "channel is empty in a correct run) — entry: <%s>", entry)
                        .doesNotContain(FILE_SECRET_VALUE);
                assertThat(entry.split("=", 2)[0])
                        .as("no companion.* key rides the env (paths ride ARGS; a value key here "
                                + "would be the AD-18 violation SEC-076 forbids)")
                        .doesNotStartWith("COMPANION_");
            }
        }
    }

    // ── row (b): DEPLOY-008 as amended (structural inertness) ────────────────────────────────────

    @Test
    @DisplayName("a secret VALUE in the container env is INERT (DEPLOY-008 as amended, owner "
            + "2026-09-11 — no guard exists): the run still boots on the mounted file-path "
            + "secrets, the ROPC token request carries the FILE's client_secret (captured at the "
            + "stand-in IdP — never the decoy), and the decoy appears in no stdout/log line")
    void envValueSecretIsInertTheMountedFileSecretIsTheOneHonored() throws Exception {
        // Both relaxed-binding spellings of the value key that must not exist:
        // COMPANION_REVERSE_MODEB_OIDC_CLIENTSECRET is the env name Spring's binder resolves to a
        // hypothetical companion.reverse.mode-b.oidc.client-secret VALUE field (uniform-form match
        // — the strongest adversarial spelling); the underscored twin is the naive spelling.
        Map<String, String> decoyEnv = Map.of(
                "COMPANION_REVERSE_MODEB_OIDC_CLIENTSECRET", ENV_DECOY_VALUE,
                "COMPANION_REVERSE_MODEB_OIDC_CLIENT_SECRET", ENV_DECOY_VALUE);
        List<String> capturedTokenForms = new CopyOnWriteArrayList<>();
        try (DockerRig rig = DockerRig.launchReverseBCell(
                IMAGE, dir, "docker-secrets-idp", decoyEnv, true, "r--r--r--", capturedTokenForms)) {
            // (1) INERT, not refused (the owner amendment): no key binds the value, so the boot
            // reaches ready solely on the mounted file-path secrets with the decoy present.
            rig.awaitStartupSummary();

            // (2) The premise is real, pinned: docker inspect's Env DOES carry the decoy — the
            // /proc/<pid>/environ + inspect leak channel is exactly why DEP-1 forbids the channel.
            String env = String.join("\n",
                    rig.container().getContainerInfo().getConfig().getEnv());
            assertThat(env)
                    .as("the decoy really is in the container env (the row's premise — the leak "
                            + "channel DEP-1 closes)")
                    .contains(ENV_DECOY_VALUE);

            // (3) One bind: ROK proves the whole chain coupled — and the ONE wire place the
            // client credential surfaces (the token request form, captured by the stand-in IdP)
            // carries the MOUNTED FILE's secret, never the env decoy. This is the bite: a future
            // value field that outranked the path (or an env fallback) turns this RED.
            Socket legacy = rig.connectLegacy();
            RelayTestFixtures.writePdu(legacy, RelayTestFixtures.bindRequest(1, "legacy1", "pw123456"));
            DockerRig.assertRokBindResp(RelayTestFixtures.readPdu(legacy), 1);
            awaitCapturedForm(capturedTokenForms);
            // CONTENT, not count: a second token fetch landing between the await and a size pin
            // is a non-defect (renewal/retry under the admission cap), so an exactly-once pin
            // would false-RED — the row's bite is that EVERY captured form carries the FILE's
            // credential and none carries the decoy.
            assertThat(capturedTokenForms)
                    .as("at least one token exchange served the bind")
                    .isNotEmpty();
            assertThat(capturedTokenForms)
                    .as("EVERY captured ROPC form's client_secret is the MOUNTED FILE's value")
                    .allSatisfy(form -> assertThat(form).contains("client_secret=" + FILE_SECRET_VALUE));
            assertThat(capturedTokenForms)
                    .as("the env decoy is honored NOWHERE — on no captured form")
                    .allSatisfy(form -> assertThat(form).doesNotContain(ENV_DECOY_VALUE));

            // (4) And in no stdout/log line either stream (the app never echoes its environment).
            assertThat(rig.stdout())
                    .as("the decoy value appears in no container stdout line")
                    .doesNotContain(ENV_DECOY_VALUE);
            assertThat(rig.stderr())
                    .as("the decoy value appears in no container stderr line")
                    .doesNotContain(ENV_DECOY_VALUE);
        }
    }

    // ── row (c): DEPLOY-009 — the two bad secret-file states ─────────────────────────────────────

    @Test
    @DisplayName("missing file AND UID-unreadable file both refuse PRE-BIND (DEPLOY-009): each "
            + "container exits non-zero at the config validation with the SEC-060/AD-18 refusal "
            + "naming the path, and reaches no startup_summary (no listener ever binds)")
    void missingAndUnreadableSecretFilesRefusePreBind() throws Exception {
        // (a) the configured path points at a file that does not exist (only the trust store is
        // mounted — the refusal names the client-secret path, the FIRST oidc content check).
        try (DockerRig rig = DockerRig.launchReverseBCell(
                IMAGE, dir, "docker-secrets-idp", Map.of(), false, null, null)) {
            long missingExit = rig.awaitContainerExit();
            String missingOut = rig.stdout() + "\n" + rig.stderr();
            assertThat(missingExit)
                    .as("the missing-file boot refuses (Spring Boot exits 1 — the manual probe's "
                            + "pinned code)")
                    .isEqualTo(1L);
            assertThat(missingOut)
                    .as("the refusal names the configured path, the missing state, and the "
                            + "fail-fast id")
                    .contains(
                            "companion.reverse.mode-b.oidc.client-secret-path=" + CLIENT_SECRET_PATH,
                            "does not exist",
                            "(OIDC client secret file missing)",
                            "SEC-060/AD-18")
                    .as("refused PRE-BIND: the validation fired during the context refresh — "
                            + "no startup_summary, no listener, no partial start")
                    .doesNotContain(STARTUP_SUMMARY_MARKER);
        }

        // (b) the file EXISTS but mode 0600 under an owner that is not 65532 (docker cp lands the
        // file root-owned): the non-root JVM's Files.isReadable refuses at startup validation.
        try (DockerRig rig = DockerRig.launchReverseBCell(
                IMAGE, dir, "docker-secrets-idp", Map.of(), true, "rw-------", null)) {
            long unreadableExit = rig.awaitContainerExit();
            String unreadableOut = rig.stdout() + "\n" + rig.stderr();
            assertThat(unreadableExit)
                    .as("the unreadable-file boot refuses (exit 1)")
                    .isEqualTo(1L);
            assertThat(unreadableOut)
                    .as("the refusal names the SAME configured path in the PERMS state — the "
                            + "CompanionConfigValidator branch the mounted-mode preservation "
                            + "(row a) makes reachable in-container")
                    .contains(
                            "companion.reverse.mode-b.oidc.client-secret-path=" + CLIENT_SECRET_PATH,
                            "is not readable",
                            "(OIDC client secret file permissions)",
                            "SEC-060/AD-18")
                    .as("refused PRE-BIND: no startup_summary, no listener, no partial start")
                    .doesNotContain(STARTUP_SUMMARY_MARKER);
        }
    }

    // ── row (d): SEC-098's image-layer arm ───────────────────────────────────────────────────────

    @Test
    @DisplayName("no secret material rides ANY layer (SEC-098 / FR-DEPLOY-4): docker save is "
            + "byte-scanned entry by entry (layers, config, manifests — blobs gunzipped when "
            + "compressed) for the exact bytes of every committed fixture cert/key/keystore plus "
            + "the rig's secret values, and docker history pins the payload to exactly the two "
            + "COPY layers")
    void noSecretMaterialRidesAnyImageLayer() throws Exception {
        DockerRig.assertContextAssembled();

        // (0) Completeness of the marker list: FIXTURE_MATERIAL must be the certs directory's
        // CLOSED set of material files (everything except generate.sh, the regeneration script
        // this row re-derives its exclusions from) — a future fixture added without joining the
        // list would silently narrow the scan.
        List<String> directoryMaterial;
        try (var entries = Files.list(FIXTURE_CERTS_DIR)) {
            directoryMaterial = entries
                    .filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString())
                    .filter(name -> !name.equals("generate.sh"))
                    .sorted()
                    .toList();
        }
        assertThat(directoryMaterial)
                .as("FIXTURE_MATERIAL is the certs directory's closed material set — the scan "
                        + "cannot silently narrow")
                .containsExactlyElementsOf(FIXTURE_MATERIAL);

        DockerClient client = DockerClientFactory.instance().client();
        String image = IMAGE.get();

        // (1) The history half of the scan: the image's payload is EXACTLY the two COPY layers
        // (jlink runtime + the one jar) — no ADD, no third payload a bake could smuggle in.
        // BOTH spellings of a COPY's created-by are matched: the daemon's `docker build` writes
        // buildkit text ("COPY jlink-image/ /opt/jre/ # buildkit") while Testcontainers' API
        // build path writes the legacy form ("/bin/sh -c #(nop) COPY dir:... in /opt/jre/") —
        // the destinations pin which payload each layer carries in either form.
        List<String> copies = client.imageHistoryCmd(image).exec().stream()
                .map(ImageHistory::getCreatedBy)
                .filter(createdBy -> createdBy != null && createdBy.contains("COPY "))
                .toList();
        assertThat(copies)
                .as("docker history: exactly two payload layers, and they are the runtime and "
                        + "the jar — the whole payload surface of the image")
                .hasSize(2);
        assertThat(String.join("\n", copies))
                .as("the two COPY layers land the runtime at /opt/jre and the jar at /opt/proxy.jar")
                .contains("/opt/jre/", "/opt/proxy.jar");

        // (2) The save half: every entry of the exported image, byte-scanned for the repo's
        // secret material. The scan covers BOTH export formats (classic layer.tar and OCI
        // blobs/sha256 — this daemon hands over OCI with UNCOMPRESSED blobs; gzip magic is
        // handled for daemons that compress). Plain entries stream through the rolling window;
        // a gzipped entry is buffered compressed for inflation (bounded by the >2 GiB refusal —
        // this image is ~137 MiB total).
        List<Marker> markers = secretMaterialMarkers();
        Path save = dir.resolve("image-save.tar");
        try (InputStream in = client.saveImageCmd(image).exec()) {
            Files.copy(in, save, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        ScanTally tally = scanImageSave(save, markers);
        assertThat(tally.entries())
                .as("the save carried real entries (a format change that scanned nothing must "
                        + "FAIL, not pass vacuously)")
                .isGreaterThanOrEqualTo(4);
        assertThat(tally.bytes())
                .as("the scanned payload covers the image's layers (the jlink runtime layer alone "
                        + "is ~101 MB — a vacuous scan cannot reach it)")
                .isGreaterThan(100_000_000L);
    }

    // ── waits and pinned literals ──────────────────────────────────────────────────────────────

    /** /proc/<pid>/status of the container's host-visible PID (the local-daemon stance). */
    private static String readProcStatus(long pid) {
        try {
            return Files.readString(Path.of("/proc", String.valueOf(pid), "status"));
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read /proc/" + pid + "/status (local daemon "
                    + "required — this suite's platform)", e);
        }
    }

    /** The four-field value line of {@code Name:} (Uid:/Gid:) from a /proc status dump. */
    private static String procIdLine(String status, String field) {
        for (String line : status.lines().toList()) {
            if (line.startsWith(field)) {
                return line.substring(field.length()).strip().replaceAll("\\s+", " ");
            }
        }
        fail("no " + field + " line in the container PID's /proc status: <" + status + ">");
        return null; // unreachable — fail() throws
    }

    /** Bounded wait for the stand-in IdP's capture (the ROK already proves the response went out). */
    private static void awaitCapturedForm(List<String> capturedTokenForms) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(10_000);
        while (capturedTokenForms.isEmpty()) {
            if (System.nanoTime() > deadline) {
                fail("the stand-in IdP captured no token request within 10s of the coupled bind");
            }
            Thread.sleep(100);
        }
    }

    // ── the layer scan (row d): markers, the tar walk, and the rolling window ────────────────────

    /** One scan marker: what it is (for the failure message) and its exact bytes. */
    private static final class Marker {
        final String description;
        final byte[] bytes;

        Marker(String description, byte[] bytes) {
            this.description = description;
            this.bytes = bytes;
        }
    }

    /** What the save scan covered (the vacuous-scan guard's evidence). */
    private static record ScanTally(int entries, long bytes) {}

    /** Loads the scan markers: every committed fixture material file + the rigs' secret values. */
    private static List<Marker> secretMaterialMarkers() {
        List<Marker> markers = new ArrayList<>();
        for (String fixture : FIXTURE_MATERIAL) {
            String resource = "/keycloak/certs/" + fixture;
            try (InputStream in = DockerSecretsE2eTest.class.getResourceAsStream(resource)) {
                if (in == null) {
                    throw new IllegalStateException("fixture resource missing: " + resource);
                }
                markers.add(new Marker("fixture " + fixture, in.readAllBytes()));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        for (String value : RUNTIME_SECRET_VALUES) {
            markers.add(new Marker("secret value <" + value + ">",
                    value.getBytes(StandardCharsets.US_ASCII)));
        }
        return markers;
    }

    /**
     * Walks the exported image's outer tar (512-byte headers; classic {@code <id>/layer.tar} and
     * OCI {@code blobs/sha256/<digest>} layouts alike) and scans EVERY regular entry for the
     * markers. Memory posture, trued: a PLAIN region streams through a rolling 64 KB window (a
     * ~101 MB layer is never held in memory), while a gzip-magic entry is held COMPRESSED in
     * memory for inflation (the mid-tar region cannot be random-access-inflated; bounded by the
     * {@code >2 GiB} refusal in {@link #scanRegion} — this rig's whole image is ~137 MiB). A
     * marker hit FAILS the row naming the entry and the material.
     */
    private static ScanTally scanImageSave(Path save, List<Marker> markers) throws IOException {
        int maxMarker = markers.stream().mapToInt(m -> m.bytes.length).max().orElseThrow();
        int entries = 0;
        long bytes = 0;
        try (FileChannel channel = FileChannel.open(save, StandardOpenOption.READ)) {
            long total = channel.size();
            long pos = 0;
            ByteBuffer header = ByteBuffer.allocate(512);
            while (pos + 512 <= total) {
                readFully(channel, header.clear(), pos);
                byte[] block = header.array();
                if (isZeroBlock(block)) {
                    break; // the terminating zero blocks
                }
                String name = tarString(block, 0, 100);
                long size = tarOctal(block, 124, 12);
                long dataStart = pos + 512;
                if (size > 0 && isRegularEntry(block[156])) {
                    entries++;
                    bytes += size;
                    scanRegion(channel, dataStart, size, name, markers, maxMarker);
                }
                long blocks = (size + 511) / 512;
                pos = dataStart + blocks * 512;
            }
        }
        return new ScanTally(entries, bytes);
    }

    /** Scans one entry's byte region (gunzipping to a spill file when the magic says so). */
    private static void scanRegion(
            FileChannel channel, long start, long size, String name,
            List<Marker> markers, int maxMarker) throws IOException {
        ByteBuffer magic = ByteBuffer.allocate(2);
        readFully(channel, magic.clear(), start);
        boolean gzip = magic.array()[0] == 0x1f && magic.array()[1] == (byte) 0x8b;
        if (gzip) {
            // The gzip path buffers the COMPRESSED blob in memory (GZIPInputStream needs the
            // whole mid-tar region — no random-access inflation), so entries too large for a
            // safe array fail CLOSED here: the plain `int` cast would silently truncate a >2 GiB
            // blob and scan garbage. This rig's image is ~137 MiB total, so the guard never
            // fires in practice; it exists to refuse a size surprise loudly.
            if (size > Integer.MAX_VALUE - 8L) {
                throw new IllegalStateException("gzipped image-save entry <" + name + "> is "
                        + size + " bytes — too large to buffer for inflation; refusing rather "
                        + "than truncate the scan");
            }
            Path spill = Files.createTempFile("image-blob-", ".bin");
            try {
                byte[] compressed = new byte[(int) size];
                readFully(channel, ByteBuffer.wrap(compressed), start);
                try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
                    Files.copy(in, spill, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
                try (InputStream in = Files.newInputStream(spill)) {
                    scanStream(name + " (gzipped)", in, markers, maxMarker);
                }
            } finally {
                Files.deleteIfExists(spill);
            }
            return;
        }
        channel.position(start);
        try (InputStream in = bounded(Channels.newInputStream(channel), size)) {
            scanStream(name, in, markers, maxMarker);
        }
    }

    /** The rolling-window marker search over one entry's stream (64 KB reads, marker-sized carry). */
    private static void scanStream(String entry, InputStream in, List<Marker> markers, int maxMarker)
            throws IOException {
        byte[] chunk = new byte[64 * 1024];
        byte[] carry = new byte[0];
        int read;
        while ((read = in.read(chunk)) > 0) {
            byte[] window = new byte[carry.length + read];
            System.arraycopy(carry, 0, window, 0, carry.length);
            System.arraycopy(chunk, 0, window, carry.length, read);
            for (Marker marker : markers) {
                if (indexOf(window, marker.bytes) >= 0) {
                    fail("image layer scan: secret material <" + marker.description
                            + "> found in save entry <" + entry + "> — FR-DEPLOY-4/SEC-098 forbids "
                            + "any baked cert/key/secret material");
                }
            }
            int keep = Math.min(window.length, maxMarker - 1);
            carry = Arrays.copyOfRange(window, window.length - keep, window.length);
        }
    }

    /** An {@link InputStream} reading at most {@code limit} bytes off the delegate. */
    private static InputStream bounded(InputStream delegate, long limit) {
        return new InputStream() {
            private long remaining = limit;

            @Override
            public int read(byte[] buffer, int offset, int length) throws IOException {
                if (remaining <= 0) {
                    return -1;
                }
                int chunk = (int) Math.min(length, remaining);
                int read = delegate.read(buffer, offset, chunk);
                if (read > 0) {
                    remaining -= read;
                }
                return read;
            }

            @Override
            public int read() throws IOException {
                if (remaining <= 0) {
                    return -1;
                }
                int b = delegate.read();
                if (b >= 0) {
                    remaining--;
                }
                return b;
            }
        };
    }

    /** Naive substring search (the marker set is small; windows are ~70 KB). */
    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** Reads {@code buffer.capacity()} bytes at {@code position} or fails (a torn save is a bug). */
    private static void readFully(FileChannel channel, ByteBuffer buffer, long position) throws IOException {
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer, position + buffer.position());
            if (read < 0) {
                throw new EOFException("docker save ended mid-tar-header at " + position);
            }
        }
    }

    /** The NUL-terminated string at {@code offset} (tar header names fit the 100-byte prefix). */
    private static String tarString(byte[] block, int offset, int length) {
        int end = offset;
        while (end < offset + length && block[end] != 0) {
            end++;
        }
        return new String(block, offset, end - offset, StandardCharsets.US_ASCII);
    }

    /** The octal size field at {@code offset} (plain-octal; docker save does not use base-256). */
    private static long tarOctal(byte[] block, int offset, int length) {
        String text = tarString(block, offset, length).strip();
        return text.isEmpty() ? 0L : Long.parseLong(text, 8);
    }

    /** Regular-file entries only ('\0', '0', '7'); directories and pax headers are skipped. */
    private static boolean isRegularEntry(byte typeFlag) {
        return typeFlag == 0 || typeFlag == '0' || typeFlag == '7';
    }

    /** The tar terminator: an all-zero header block. */
    private static boolean isZeroBlock(byte[] block) {
        for (byte b : block) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
