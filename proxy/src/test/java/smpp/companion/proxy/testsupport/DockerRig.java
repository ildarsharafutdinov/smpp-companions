package smpp.companion.proxy.testsupport;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import com.sun.net.httpserver.HttpsServer;

import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.OutputFrame;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

import smpp.companion.proxy.relay.MockSmsc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Story 6.2 T1 (ledger fold, deferred-work BH7) — the shared DISTROLESS-CONTAINER rig of the two
 * 5.2 Docker suites: one reverse-B cell as the T2 image ({@code ImageFromDockerfile} over the
 * {@code :proxy:assembleDockerContext} output), its two host-side satellites ({@link MockSmsc}
 * and the docker-reachable IMMEDIATE-allow token stand-in, both reached through the Testcontainers
 * host-access portal), the boot/exit waits, the in-container probe exec, and the pinned ROK
 * bind_resp contract. Formerly duplicated as the private {@code DockerRig} inner classes and
 * launch/args/wait/probe helpers of {@code DockerImageBootSmokeTest} (5.2 T3) and {@code
 * DockerSecretsE2eTest} (5.2 T4); one home before the third consumer (Story 6.2 T3's composed
 * two-container leg), the 4.2/4.3 fixture-fold precedent (one public-final-class home, static
 * factories, caller-owned handles).
 *
 * <p><b>The recorded T3/T4 drift is reconciled HERE, once.</b> The 5.2 T4 suite grew a LIVE-inspect
 * {@code isRunning()}/{@code exitCode()} pair (raw docker-inspect, never Testcontainers' cached
 * start state) while T3 still polled {@code container.isRunning()}; the live pair is the rig's
 * single behavior now, consumed by every wait and both folded suites — a container that dies
 * mid-wait is reported through a live inspect that names its exit code.
 *
 * <p><b>Caller-owned handles</b> (the fixture-fold rule): the per-suite image (own reaper tag —
 * {@link #suiteImage}), the temp dir the secret material lands in, the container-env map, and the
 * stand-in IdP's form-capture list all belong to the caller; the rig owns only the container, the
 * satellites, and the coupled pair's legacy leg. {@link #close()} is idempotent and
 * exception-safe (the house rule): a failed row must not strand the container, the mock's loop,
 * or the stand-in's executor. Docker-daemon gating is the SUITES' concern ({@code
 * @Testcontainers(disabledWithoutDocker = true)}), not the rig's.
 */
public final class DockerRig implements AutoCloseable {

    /** The assembled T2 context ({@code :proxy:assembleDockerContext} output — the suite's input). */
    private static final Path DOCKER_CONTEXT = Path.of("build", "docker-image");

    private static final Path DOCKERFILE_IN_CONTEXT = DOCKER_CONTEXT.resolve("Dockerfile");

    private static final Path JLINK_RUNTIME_IN_CONTEXT = DOCKER_CONTEXT.resolve("jlink-image");

    private static final Path PROXY_JAR_IN_CONTEXT = DOCKER_CONTEXT.resolve("proxy.jar");

    /**
     * The compiled test classes' {@code smpp} tree &mdash; {@code docker cp}d to {@code /smpp} so
     * the image's own java can run the bootstrap suite's {@code DockerContainerProbe} via {@code
     * -cp /} (the probe is the ONLY class ever loaded from the copy). On the test runtime
     * classpath, so a probe edit already re-runs {@code :proxy:test}.
     */
    private static final Path TEST_CLASSES_SMPP_TREE = Path.of("build", "classes", "java", "test", "smpp");

    /** The image's ENTRYPOINT java path (the Dockerfile's {@code <jre>}/bin/java). */
    private static final String ENTRYPOINT_JAVA = "/opt/jre/bin/java";

    /** The in-container probe's FQCN (docker-cp'd as /smpp/companion/...). */
    private static final String PROBE_FQCN = "smpp.companion.proxy.bootstrap.DockerContainerProbe";

    /** The DEP-1 mount point: the only secret channel the container shape honors. */
    private static final String SECRETS_DIR = "/run/secrets";

    /**
     * The mounted client-secret FILE's value — the credential every folded rig mounts (and the
     * T4 secrets rows prove is the one honored, never an env decoy).
     */
    public static final String MOUNTED_CLIENT_SECRET_VALUE = "docker-smoke-secret";

    /** The pinned boot-summary stdout marker (identical literal to the JAR-shape smoke). */
    public static final String STARTUP_SUMMARY_MARKER = "\"event\":\"startup_summary\"";

    /** The bind_resp wire contract, pinned as a LITERAL (the RelayA1SmokeTest discipline). */
    private static final int BIND_TRANSCEIVER_RESP = 0x80000009;

    /** The container boot/refusal deadline (image boot + Spring on a loaded CI runner). */
    private static final long BOOT_DEADLINE_MILLIS = 90_000;

    private final GenericContainer<?> container;
    private final MockSmsc smsc;
    private final HttpsServer idp;
    private final int bindPort;

    /** The coupled pair's legacy leg — HELD OPEN (the drain rows' live pair) until {@link #close()}. */
    private Socket legacy;

    private DockerRig(GenericContainer<?> container, MockSmsc smsc, HttpsServer idp, int bindPort) {
        this.container = container;
        this.smsc = smsc;
        this.idp = idp;
        this.bindPort = bindPort;
    }

    /**
     * The image a suite builds and boots &mdash; from the SAME three-entry context {@code
     * :proxy:dockerImage} assembles (Dockerfile + jlink runtime + the one boot jar, modes
     * normalized &mdash; one image definition, no drift). The PER-SUITE reaper-tagged tag stays
     * the caller's ({@code smpp-proxy:t3-suite} / {@code smpp-proxy:t4-suite} in the folded
     * consumers) so each suite's image lifecycle is its own; a new consumer passes its own tag.
     * {@link ImageFromDockerfile} resolves lazily (first container start / first {@code get()}),
     * once per test JVM.
     */
    public static ImageFromDockerfile suiteImage(String tag) {
        return new ImageFromDockerfile(tag)
                .withFileFromPath("Dockerfile", DOCKERFILE_IN_CONTEXT)
                .withFileFromPath("jlink-image", JLINK_RUNTIME_IN_CONTEXT)
                .withFileFromPath("proxy.jar", PROXY_JAR_IN_CONTEXT);
    }

    /**
     * Launches the reverse-B cell as the T2 image, the correctly-configured shape: the client
     * secret FILE mounted world-readable ({@code r--r--r--}) beside the always-world-readable
     * trust store, no container env. The 5.2 T3 suite's own launch, kept as the simple factory.
     */
    public static DockerRig launchReverseBCell(
            ImageFromDockerfile image, Path secretsDir, String idpThreadName) throws IOException {
        return launchReverseBCell(image, secretsDir, idpThreadName, Map.of(), true, "r--r--r--", null);
    }

    /**
     * Launches the reverse-B cell as the T2 image with the T4 knobs: {@code containerEnv} rides
     * {@code docker run -e} (the decoy rows; empty for correctly-configured rows), and the
     * client-secret FILE is mounted when {@code mountClientSecret} is set with the given POSIX
     * mode string ({@code "r--r--r--"} readable-by-all / {@code "rw-------"} owner-only &mdash;
     * docker cp preserves the modes, and the files land root-owned, so 0600 denies the container
     * UID). {@code capturedTokenForms} (nullable) is the stand-in IdP's form capture (caller-owned
     * list). The trust store always mounts world-readable &mdash; the rows vary only the
     * client-secret file, the DEP-1 contract's own credential.
     *
     * <p>The container carries the cell args (the CMD pass-through appended AFTER the exec-form
     * ENTRYPOINT &mdash; exactly the JAR shape's arg surface), the secret material docker-cp'd to
     * {@code /run/secrets}, and the compiled probe tree at {@code /smpp}. The satellites are
     * exposed to the container BEFORE start via the host-access portal. A rig that fails to
     * build must not strand what it already created &mdash; the caller's try-with-resources never
     * engages when launch never returned (the house rule).
     */
    public static DockerRig launchReverseBCell(
            ImageFromDockerfile image, Path secretsDir, String idpThreadName,
            Map<String, String> containerEnv, boolean mountClientSecret, String clientSecretPerms,
            List<String> capturedTokenForms) throws IOException {
        assertContextAssembled();
        assertThat(TEST_CLASSES_SMPP_TREE)
                .as("the compiled test classes must exist (:proxy:test compiles them first)")
                .isDirectory();
        MockSmsc smsc = MockSmsc.start();
        HttpsServer idp = null;
        GenericContainer<?> container = null;
        try {
            idp = TokenIdpStandIn.dockerHostAllowIdp(
                    new CountDownLatch(1), new CountDownLatch(1), false, idpThreadName,
                    capturedTokenForms);
            int bindPort = RelayTestFixtures.freePort();

            // the host-side satellites, reachable from the container by name (the portal forwards
            // to this JVM's loopback — the satellites stay exactly where the JAR-shape rig puts them)
            org.testcontainers.Testcontainers.exposeHostPorts(smsc.port(), idp.getAddress().getPort());

            Path secrets = secretsDir.resolve("secrets");
            Files.createDirectories(secrets);
            if (mountClientSecret) {
                Path secret = Files.writeString(
                        secrets.resolve("oidc-client-secret"), MOUNTED_CLIENT_SECRET_VALUE + "\n");
                Files.setPosixFilePermissions(secret, PosixFilePermissions.fromString(clientSecretPerms));
            }
            Path trustStore = RelayTestFixtures.idpTrustStoreFixture(secrets.resolve("idp-truststore.p12"));
            Files.setPosixFilePermissions(trustStore, PosixFilePermissions.fromString("r--r--r--"));

            GenericContainer<?> cell = new GenericContainer<>(image)
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

    /** The distroless container itself (rows inspect the raw client through this handle). */
    public GenericContainer<?> container() {
        return container;
    }

    /** The host-side loopback {@link MockSmsc} satellite (reached through the portal). */
    public MockSmsc smsc() {
        return smsc;
    }

    /** The cell's configured SMPP bind port (the PUBLISHED port's container-side number). */
    public int bindPort() {
        return bindPort;
    }

    /** A legacy client on the container's PUBLISHED SMPP port (the RelayA1SmokeTest idiom). */
    public Socket connectLegacy() throws IOException {
        Socket socket = new Socket(container.getHost(), container.getMappedPort(bindPort));
        socket.setSoTimeout(10_000);
        legacy = socket;
        return socket;
    }

    /**
     * Bounded poll for the boot summary on the container's stdout, failing FAST (with the
     * captured docker logs AND the live-inspected exit code) if the container dies first — a
     * refused boot must surface its own refusal text, never a 90s wait. The refusal rows' own
     * variant is {@link #awaitContainerExit()}.
     */
    public void awaitStartupSummary() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(BOOT_DEADLINE_MILLIS);
        while (!stdout().contains(STARTUP_SUMMARY_MARKER)) {
            if (!isRunning()) {
                fail("the container exited (code " + exitCode() + ") before startup_summary — "
                        + "docker logs: <" + stdout() + ">, <" + stderr() + ">");
            }
            if (System.nanoTime() > deadline) {
                fail("no startup_summary within " + BOOT_DEADLINE_MILLIS + "ms — docker logs so far: <"
                        + stdout() + ">, <" + stderr() + ">");
            }
            Thread.sleep(200);
        }
    }

    /**
     * Bounded poll for the REFUSED boot's terminal state: the container exits on its own at
     * startup validation (~1s in-container; bounded by the boot deadline regardless), and the
     * LIVE inspect (never Testcontainers' cached start state) reports its exit code.
     */
    public long awaitContainerExit() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(BOOT_DEADLINE_MILLIS);
        while (isRunning()) {
            if (System.nanoTime() > deadline) {
                fail("the container did not exit within " + BOOT_DEADLINE_MILLIS
                        + "ms — a refused boot must die on its own, never hang: <" + stdout()
                        + ">, <" + stderr() + ">");
            }
            Thread.sleep(200);
        }
        return exitCode();
    }

    /** LIVE running-state via the raw client (the BH7 drift reconciliation: the ONE behavior). */
    public boolean isRunning() {
        return Boolean.TRUE.equals(container.getDockerClient()
                .inspectContainerCmd(container.getContainerId())
                .exec()
                .getState()
                .getRunning());
    }

    /** LIVE exit code via the raw client (the container is terminal when this is read). */
    public long exitCode() {
        Long code = container.getDockerClient()
                .inspectContainerCmd(container.getContainerId())
                .exec()
                .getState()
                .getExitCodeLong();
        return code == null ? -1L : code;
    }

    /** The container's stdout (docker keeps the streams separately fetchable). */
    public String stdout() {
        return container.getLogs(OutputFrame.OutputType.STDOUT);
    }

    /** The container's stderr. */
    public String stderr() {
        return container.getLogs(OutputFrame.OutputType.STDERR);
    }

    /**
     * Runs the cp'd probe inside the container with the IMAGE'S OWN java (no shell exists to
     * wrap it — Testcontainers execs the command vector directly).
     */
    public Container.ExecResult execProbe(String mode, String arg)
            throws IOException, InterruptedException {
        return container.execInContainer(ENTRYPOINT_JAVA, "-cp", "/", PROBE_FQCN, mode, arg);
    }

    /**
     * Fail-closed guard: the suite docker-builds from the assembled context, so the context (and
     * the inputs that produce it) must exist before any row touches the image — the message names
     * the Gradle wiring rather than letting Testcontainers fail on a missing build-context file.
     */
    public static void assertContextAssembled() {
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

    /** The pinned ROK bind_resp contract, asserted on LITERALS (independent of production constants). */
    public static void assertRokBindResp(byte[] resp, int expectedSequence) {
        java.nio.ByteBuffer header = java.nio.ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the resp's command_length covers the whole PDU").isEqualTo(resp.length);
        assertThat(commandId).as("bind_transceiver answered by bind_transceiver_resp")
                .isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(commandStatus)
                .as("ESME_ROK — the containerized chain coupled (verdict Allow at the stand-in IdP "
                        + "over the host-access portal → egress dial → the mock's ROK)")
                .isZero();
        assertThat(sequence).as("the resp answers the request's sequence_number").isEqualTo(expectedSequence);
    }

    /**
     * The reverse-B cell as CONTAINER args (the CMD pass-through = the {@code docker run <image>
     * <args>} surface appended after the ENTRYPOINT — the same Spring run-args channel the JAR
     * shape's arg list rides; args outrank application.yml). The yml supplies everything else:
     * the metrics port (9090 — deliberately NOT overridden: DEPLOY-011's literal-loopback bind),
     * the TLS lists, the 4s adjudication deadline, the 30s idle window, the memory trio, and
     * {@code budget-check: fail}. NO {@code companion.memory.*} keys and NO {@code
     * companion.metrics.*} key, deliberately (the interlock and the loopback-only scrape both pin
     * the SHIPPED defaults). The listener binds the container wildcard so the PUBLISHED port can
     * reach it; the SMSC and the IdP are named through the host-access name, not localhost (a
     * container's loopback is its own).
     */
    private static List<String> cellArgs(HttpsServer idp, int smscPort, int bindPort) {
        return List.of(
                "--companion.bind.host=0.0.0.0",
                "--companion.bind.port=" + bindPort,
                "--companion.shutdown.drain-timeout=2s",
                "--companion.reverse.mode-b.smsc.host=" + TokenIdpStandIn.DOCKER_GATEWAY_HOST,
                "--companion.reverse.mode-b.smsc.port=" + smscPort,
                "--companion.reverse.mode-b.acknowledged=true",
                "--companion.reverse.mode-b.oidc.provider-url=" + TokenIdpStandIn.dockerHostRealmBase(idp),
                "--companion.reverse.mode-b.oidc.client-id=smpp-client-confidential",
                "--companion.reverse.mode-b.oidc.client-secret-path=" + SECRETS_DIR + "/oidc-client-secret",
                "--companion.reverse.mode-b.oidc.trust-store.path=" + SECRETS_DIR + "/idp-truststore.p12",
                "--companion.reverse.mode-b.oidc.trust-store.password=" + RelayTestFixtures.IDP_STORE_PASSWORD,
                "--companion.reverse.mode-b.oidc.timeout=4s",
                "--companion.reverse.mode-b.oidc.max-in-flight=64");
    }

    @Override
    public void close() {
        if (legacy != null) {
            try {
                legacy.close();
            } catch (IOException ignored) {
                // teardown best-effort — the walk's own close is what the row asserts
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
