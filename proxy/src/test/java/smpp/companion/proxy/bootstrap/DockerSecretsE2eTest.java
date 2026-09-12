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
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.model.ImageHistory;
import com.sun.net.httpserver.HttpsServer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.OutputFrame;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import smpp.companion.proxy.relay.MockSmsc;
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.testsupport.TokenIdpStandIn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Story 5.2 T4 &mdash; the Docker secrets E2E (DEP-1, FR-DEPLOY-4): the SAME rig as {@link
 * DockerImageBootSmokeTest} (the T2 distroless image over the one boot jar, the host-access
 * satellites, the cp'd {@link DockerContainerProbe}) proving the secrets contract end to end in
 * the container shape.
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

    /** The assembled T2 context ({@code :proxy:assembleDockerContext} output — the suite's input). */
    private static final Path DOCKER_CONTEXT = Path.of("build", "docker-image");

    private static final Path DOCKERFILE_IN_CONTEXT = DOCKER_CONTEXT.resolve("Dockerfile");

    private static final Path JLINK_RUNTIME_IN_CONTEXT = DOCKER_CONTEXT.resolve("jlink-image");

    private static final Path PROXY_JAR_IN_CONTEXT = DOCKER_CONTEXT.resolve("proxy.jar");

    /**
     * The compiled test classes' {@code smpp} tree &mdash; {@code docker cp}d to {@code /smpp} so
     * the image's own java can run {@link DockerContainerProbe} (row (a)'s readability stat runs
     * under the container's UID).
     */
    private static final Path TEST_CLASSES_SMPP_TREE = Path.of("build", "classes", "java", "test", "smpp");

    /**
     * The image this suite builds and boots &mdash; the SAME three-entry context {@code
     * :proxy:dockerImage} assembles (one image definition with T3's suite; own tag so each suite's
     * reaper-tagged lifecycle stays its own). {@link ImageFromDockerfile} resolves lazily, once
     * per test JVM.
     */
    private static final ImageFromDockerfile IMAGE = new ImageFromDockerfile("smpp-proxy:t4-suite")
            .withFileFromPath("Dockerfile", DOCKERFILE_IN_CONTEXT)
            .withFileFromPath("jlink-image", JLINK_RUNTIME_IN_CONTEXT)
            .withFileFromPath("proxy.jar", PROXY_JAR_IN_CONTEXT);

    /** The image's ENTRYPOINT java path (exec'd for the in-container probe). */
    private static final String ENTRYPOINT_JAVA = "/opt/jre/bin/java";

    /** The in-container probe's FQCN (docker-cp'd as /smpp/companion/...). */
    private static final String PROBE_FQCN = "smpp.companion.proxy.bootstrap.DockerContainerProbe";

    /** The DEP-1 mount point: the only secret channel the container shape honors. */
    private static final String SECRETS_DIR = "/run/secrets";

    private static final String CLIENT_SECRET_PATH = SECRETS_DIR + "/oidc-client-secret";

    private static final String TRUST_STORE_PATH = SECRETS_DIR + "/idp-truststore.p12";

    /** The mounted client-secret FILE's value — the credential the row proves is honored. */
    private static final String FILE_SECRET_VALUE = "docker-smoke-secret";

    /**
     * The container-env decoy value — secret MATERIAL deliberately injected through the channel
     * DEP-1 forbids, under both relaxed-binding spellings of the value key (row (b)'s premise).
     */
    private static final String ENV_DECOY_VALUE = "env-injected-decoy-secret";

    /** The distroless {@code nonroot} UID/GID (base-debian12:nonroot, fixed at 65532). */
    private static final String NONROOT_UID = "65532";

    // ── the pinned stdout markers (identical literals to the T3/JAR-shape smokes) ────────────────

    private static final String STARTUP_SUMMARY_MARKER = "\"event\":\"startup_summary\"";

    /** The bind_resp wire contract, pinned as a LITERAL (the RelayA1SmokeTest discipline). */
    private static final int BIND_TRANSCEIVER_RESP = 0x80000009;

    /** The container boot/refusal deadline (image boot + Spring on a loaded CI runner). */
    private static final long BOOT_DEADLINE_MILLIS = 90_000;

    /**
     * The committed fixture PKI ({@code keycloak/certs/}, {@code generate.sh}) &mdash; every
     * cert/key/keystore file, whose EXACT BYTES are the layer-scan markers (row (d)). {@code
     * generate.sh} itself and the CA certs' .pem twins are covered by their p12/PEM bytes; the
     * list is the directory's closed set of material files.
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
        try (DockerRig rig = launchReverseBCell(Map.of(), true, "r--r--r--", null)) {
            awaitStartupSummary(rig);

            // (1) The runtime UID/GID, from the LIVE process (not the image text): docker inspect's
            // State.Pid is the container's PID-1 java as seen by the HOST kernel; its /proc status
            // pins every UID/GID field to the distroless nonroot 65532.
            long pid = rig.container.getContainerInfo().getState().getPidLong();
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
                Container.ExecResult stat = execProbe(rig, "readable", secret);
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
            String[] env = rig.container.getContainerInfo().getConfig().getEnv();
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
        try (DockerRig rig = launchReverseBCell(decoyEnv, true, "r--r--r--", capturedTokenForms)) {
            // (1) INERT, not refused (the owner amendment): no key binds the value, so the boot
            // reaches ready solely on the mounted file-path secrets with the decoy present.
            awaitStartupSummary(rig);

            // (2) The premise is real, pinned: docker inspect's Env DOES carry the decoy — the
            // /proc/<pid>/environ + inspect leak channel is exactly why DEP-1 forbids the channel.
            String env = String.join("\n",
                    rig.container.getContainerInfo().getConfig().getEnv());
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
            assertRokBindResp(RelayTestFixtures.readPdu(legacy), 1);
            awaitCapturedForm(capturedTokenForms);
            assertThat(capturedTokenForms)
                    .as("exactly one token exchange served the bind")
                    .hasSize(1);
            assertThat(capturedTokenForms.get(0))
                    .as("the ROPC form's client_secret is the MOUNTED FILE's value")
                    .contains("client_secret=" + FILE_SECRET_VALUE)
                    .as("the env decoy is honored NOWHERE — not on the credential's one wire "
                            + "surface")
                    .doesNotContain(ENV_DECOY_VALUE);

            // (4) And in no stdout/log line either stream (the app never echoes its environment).
            assertThat(stdout(rig))
                    .as("the decoy value appears in no container stdout line")
                    .doesNotContain(ENV_DECOY_VALUE);
            assertThat(stderr(rig))
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
        try (DockerRig rig = launchReverseBCell(Map.of(), false, null, null)) {
            long missingExit = awaitContainerExit(rig);
            String missingOut = stdout(rig) + "\n" + stderr(rig);
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
        try (DockerRig rig = launchReverseBCell(Map.of(), true, "rw-------", null)) {
            long unreadableExit = awaitContainerExit(rig);
            String unreadableOut = stdout(rig) + "\n" + stderr(rig);
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
        assertContextAssembled();
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
        // handled for daemons that compress), streaming with a rolling window (a ~101 MB layer
        // is never held in memory).
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

    // ── the rig: the container + its host-side satellites (the T3 rig + T4's knobs) ─────────────

    /**
     * Everything one row holds: the distroless container, its captured docker streams, and the
     * two loopback satellites ({@link MockSmsc} and the docker-reachable IMMEDIATE-allow token
     * stand-in), both reached through the Testcontainers host-access portal. {@link #close()} is
     * idempotent and exception-safe (the house rule).
     */
    private static final class DockerRig implements AutoCloseable {

        final GenericContainer<?> container;
        final MockSmsc smsc;
        final HttpsServer idp;
        final int bindPort;

        /** The coupled pair's legacy leg (row (b) holds it until the row's assertions are done). */
        Socket legacy;

        DockerRig(GenericContainer<?> container, MockSmsc smsc, HttpsServer idp, int bindPort) {
            this.container = container;
            this.smsc = smsc;
            this.idp = idp;
            this.bindPort = bindPort;
        }

        /** A legacy client on the container's PUBLISHED SMPP port (the RelayA1SmokeTest idiom). */
        Socket connectLegacy() throws IOException {
            Socket socket = new Socket(container.getHost(), container.getMappedPort(bindPort));
            socket.setSoTimeout(10_000);
            legacy = socket;
            return socket;
        }

        @Override
        public void close() {
            if (legacy != null) {
                try {
                    legacy.close();
                } catch (IOException ignored) {
                    // teardown best-effort
                }
            }
            try {
                container.stop(); // no-op-safe on an already-stopped container
            } catch (RuntimeException ignored) {
                // already stopped/removed — Ryuk owns the remainder
            }
            try {
                smsc.close();
            } catch (Exception ignored) {
                // already closed
            }
            try {
                idp.stop(0);
            } catch (Exception ignored) {
                // already stopped
            }
        }
    }

    /**
     * Launches the reverse-B cell as the T2 image with T4's knobs: {@code containerEnv} rides
     * {@code docker run -e} (row (b)'s decoys; empty for correctly-configured rows), and the
     * client-secret FILE is mounted when {@code mountClientSecret} is set with the given POSIX
     * mode string ({@code "r--r--r--"} readable-by-all / {@code "rw-------"} owner-only — the
     * docker cp preserves the modes, and the files land root-owned, so 0600 denies the container
     * UID). {@code capturedTokenForms} (nullable) is the stand-in IdP's form capture. The
     * trust store always mounts world-readable — the rows vary only the client-secret file, the
     * DEP-1 contract's own credential.
     */
    private DockerRig launchReverseBCell(Map<String, String> containerEnv, boolean mountClientSecret,
            String clientSecretPerms, List<String> capturedTokenForms) throws IOException {
        assertContextAssembled();
        assertThat(TEST_CLASSES_SMPP_TREE)
                .as("the compiled test classes must exist (:proxy:test compiles them first)")
                .isDirectory();
        MockSmsc smsc = MockSmsc.start();
        HttpsServer idp = null;
        GenericContainer<?> container = null;
        try {
            idp = TokenIdpStandIn.dockerHostAllowIdp(
                    new CountDownLatch(1), new CountDownLatch(1),
                    false, "docker-secrets-idp", capturedTokenForms);
            int bindPort = RelayTestFixtures.freePort();
            org.testcontainers.Testcontainers.exposeHostPorts(smsc.port(), idp.getAddress().getPort());

            Path secrets = dir.resolve("secrets");
            Files.createDirectories(secrets);
            if (mountClientSecret) {
                Path secret = Files.writeString(
                        secrets.resolve("oidc-client-secret"), FILE_SECRET_VALUE + "\n");
                Files.setPosixFilePermissions(secret, PosixFilePermissions.fromString(clientSecretPerms));
            }
            Path trustStore = RelayTestFixtures.idpTrustStoreFixture(secrets.resolve("idp-truststore.p12"));
            Files.setPosixFilePermissions(trustStore, PosixFilePermissions.fromString("r--r--r--"));

            GenericContainer<?> cell = new GenericContainer<>(IMAGE)
                    .withAccessToHost(true)
                    .withExposedPorts(bindPort)
                    .withCommand(cellArgs(idp, smsc.port(), bindPort).toArray(String[]::new))
                    .withCopyFileToContainer(MountableFile.forHostPath(secrets), SECRETS_DIR)
                    .withCopyFileToContainer(MountableFile.forHostPath(TEST_CLASSES_SMPP_TREE), "/smpp");
            containerEnv.forEach(cell::withEnv);
            container = cell;
            container.start();
            return new DockerRig(container, smsc, idp, bindPort);
        } catch (RuntimeException | Error | IOException e) {
            // a rig that fails to build must not strand what it already created (the house rule).
            if (container != null) {
                try {
                    container.stop();
                } catch (RuntimeException ignored) {
                    // best-effort teardown on the failure path
                }
            }
            if (idp != null) {
                idp.stop(0);
            }
            smsc.close();
            throw e;
        }
    }

    /**
     * The reverse-B cell as CONTAINER args — the identical arg list to the T3 suite's rig (the
     * CMD pass-through = the JAR shape's arg surface; args outrank application.yml), so both
     * suites boot the SAME cell against the SAME satellites.
     */
    private List<String> cellArgs(HttpsServer idp, int smscPort, int bindPort) {
        return List.of(
                "--companion.bind.host=0.0.0.0",
                "--companion.bind.port=" + bindPort,
                "--companion.shutdown.drain-timeout=2s",
                "--companion.reverse.mode-b.smsc.host=" + TokenIdpStandIn.DOCKER_GATEWAY_HOST,
                "--companion.reverse.mode-b.smsc.port=" + smscPort,
                "--companion.reverse.mode-b.acknowledged=true",
                "--companion.reverse.mode-b.oidc.provider-url=" + TokenIdpStandIn.dockerHostRealmBase(idp),
                "--companion.reverse.mode-b.oidc.client-id=smpp-client-confidential",
                "--companion.reverse.mode-b.oidc.client-secret-path=" + CLIENT_SECRET_PATH,
                "--companion.reverse.mode-b.oidc.trust-store.path=" + TRUST_STORE_PATH,
                "--companion.reverse.mode-b.oidc.trust-store.password=" + RelayTestFixtures.IDP_STORE_PASSWORD,
                "--companion.reverse.mode-b.oidc.timeout=4s",
                "--companion.reverse.mode-b.oidc.max-in-flight=64");
    }

    // ── waits, probes, and pinned literals ──────────────────────────────────────────────────────

    /**
     * Fail-closed guard: identical to the T3 suite's (the suite docker-builds from the assembled
     * context, so it must exist before any row touches the image).
     */
    private static void assertContextAssembled() {
        assertThat(DOCKERFILE_IN_CONTEXT)
                .as("the assembled docker context exists (:proxy:assembleDockerContext — wired into "
                        + ":proxy:test; a manual run is ./gradlew :proxy:test)")
                .isRegularFile();
        assertThat(JLINK_RUNTIME_IN_CONTEXT.resolve("bin/java"))
                .as("the context carries the jlink runtime")
                .isRegularFile();
        assertThat(PROXY_JAR_IN_CONTEXT)
                .as("the context carries the ONE boot jar (byte-for-byte 5.1's artifact)")
                .isRegularFile();
    }

    /**
     * Bounded poll for the boot summary on the container's stdout, failing FAST (with the captured
     * docker logs) if the container dies first — the refusal rows' own variant is {@link
     * #awaitContainerExit}.
     */
    private static void awaitStartupSummary(DockerRig rig) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(BOOT_DEADLINE_MILLIS);
        while (!stdout(rig).contains(STARTUP_SUMMARY_MARKER)) {
            if (!isRunning(rig)) {
                fail("the container exited (code " + exitCode(rig) + ") before startup_summary — "
                        + "docker logs: <" + stdout(rig) + ">, <" + stderr(rig) + ">");
            }
            if (System.nanoTime() > deadline) {
                fail("no startup_summary within " + BOOT_DEADLINE_MILLIS + "ms — docker logs so far: <"
                        + stdout(rig) + ">, <" + stderr(rig) + ">");
            }
            Thread.sleep(200);
        }
    }

    /**
     * Bounded poll for the REFUSED boot's terminal state: the container exits on its own at
     * startup validation (~1s in-container; bounded by the boot deadline regardless), and the
     * LIVE inspect (never Testcontainers' cached start state) reports its exit code.
     */
    private static long awaitContainerExit(DockerRig rig) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(BOOT_DEADLINE_MILLIS);
        while (isRunning(rig)) {
            if (System.nanoTime() > deadline) {
                fail("the container did not exit within " + BOOT_DEADLINE_MILLIS
                        + "ms — a refused boot must die on its own, never hang: <" + stdout(rig)
                        + ">, <" + stderr(rig) + ">");
            }
            Thread.sleep(200);
        }
        return exitCode(rig);
    }

    /** LIVE running-state via the raw client (the T3 stop row's inspect idiom). */
    private static boolean isRunning(DockerRig rig) {
        return Boolean.TRUE.equals(rig.container.getDockerClient()
                .inspectContainerCmd(rig.container.getContainerId())
                .exec()
                .getState()
                .getRunning());
    }

    /** LIVE exit code via the raw client (the container is terminal when this is read). */
    private static long exitCode(DockerRig rig) {
        Long code = rig.container.getDockerClient()
                .inspectContainerCmd(rig.container.getContainerId())
                .exec()
                .getState()
                .getExitCodeLong();
        return code == null ? -1L : code;
    }

    /** The container's stdout (docker keeps the streams separately fetchable). */
    private static String stdout(DockerRig rig) {
        return rig.container.getLogs(OutputFrame.OutputType.STDOUT);
    }

    /** The container's stderr. */
    private static String stderr(DockerRig rig) {
        return rig.container.getLogs(OutputFrame.OutputType.STDERR);
    }

    /** Runs the cp'd probe inside the container with the IMAGE'S OWN java. */
    private Container.ExecResult execProbe(DockerRig rig, String mode, String arg)
            throws IOException, InterruptedException {
        return rig.container.execInContainer(ENTRYPOINT_JAVA, "-cp", "/", PROBE_FQCN, mode, arg);
    }

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

    /** The pinned ROK bind_resp contract, asserted on LITERALS (independent of production constants). */
    private static void assertRokBindResp(byte[] resp, int expectedSequence) {
        ByteBuffer header = ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the resp's command_length covers the whole PDU").isEqualTo(resp.length);
        assertThat(commandId).as("bind_transceiver answered by bind_transceiver_resp")
                .isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(commandStatus)
                .as("ESME_ROK — the chain coupled on the mounted file-path secret (the env decoy "
                        + "bound nothing)")
                .isZero();
        assertThat(sequence).as("the resp answers the request's sequence_number").isEqualTo(expectedSequence);
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
    private record ScanTally(int entries, long bytes) {}

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
     * markers: gzip-magic entries are inflated to a spill file first (this daemon's blobs are
     * uncompressed; compressed-blob daemons are covered), and each region is read through a
     * rolling window so a ~101 MB layer is never held in memory. A marker hit FAILS the row
     * naming the entry and the material.
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
