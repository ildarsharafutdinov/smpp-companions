package smpp.companion.proxy.bootstrap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.StandardSocketOptions;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

/**
 * Story 5.2 T3 &mdash; the {@code docker cp}-able in-container probe for the distroless boot+smoke
 * suite. Distroless has no shell, no curl, no coreutils, so every in-container observation runs via
 * {@code docker exec} of the IMAGE'S OWN {@code java} against THIS class (compiled at test time,
 * copied into the running container, executed as {@code /opt/jre/bin/java -cp / <FQCN> <mode> ...}).
 * It is deliberately {@code java.base}-only (raw sockets; the JDK 16+ AF_UNIX {@code SocketChannel}
 * for the attach socket) so the jlink runtime's module set runs it unchanged.
 *
 * <p>Modes:
 * <ul>
 *   <li>{@code scrape <port>} &mdash; GET {@code /metrics} on the literal 127.0.0.1 inside the
 *       container (DEPLOY-011's Docker arm: the loopback-metrics endpoint is reachable ONLY
 *       in-container) and print the raw response. Exit 0 only on a complete read.</li>
 *   <li>{@code readable <path>} &mdash; stat {@code path} AS THE CONTAINER'S OWN USER ({@code
 *       docker exec} runs the probe under the image's non-root UID 65532, so {@code
 *       Files.isReadable} is the real access(2) of the non-root JVM &mdash; DEPLOY-007's
 *       load-bearing half, "the mounted secret is readable by this UID"). Prints {@code
 *       readable <path> perms=<posix> size=<n>} and exits 0 when readable; prints the same
 *       line prefixed {@code unreadable} and exits 3 when the UID cannot read it (the
 *       distroless base has no ls/stat to ask).</li>
 *   <li>{@code prepare-attach <pid>} &mdash; create {@code /tmp/.attach_pid<pid>}, the file whose
 *       presence makes the target JVM's SIGQUIT handler start its (lazy) attach listener instead of
 *       only dumping threads.</li>
 *   <li>{@code force-gc <pid>} &mdash; speak the JDK attach protocol by hand over the AF_UNIX socket
 *       {@code /tmp/.java_pid<pid>} ({@code jcmd GC.run}): the exec'd JVM cannot use {@code
 *       com.sun.tools.attach} (the jlink image carries no {@code jdk.attach} module) and the target
 *       runs no JMX agent, so this is the one deterministic way to force a GC cycle in the PID-1
 *       proxy &mdash; the cycle Micrometer's {@code jvm_gc_*} timer families are created lazily on
 *       (DEPLOY-004's deferred introspection arm; spec: "deterministic after a forced cycle"). The
 *       completion status (the trailing {@code 0} line) is printed; a non-zero status exits 3.</li>
 * </ul>
 *
 * <p>Test-tier only; never discovered by JUnit (no test methods). The wire format follows the JDK's
 * own {@code HotSpotVirtualMachine.writeCommand}: NUL-terminated strings, protocol version first,
 * then the command, then exactly three arguments (v1 pads missing ones empty).
 */
public final class DockerContainerProbe {

    private DockerContainerProbe() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: DockerContainerProbe scrape|readable|prepare-attach|force-gc <arg>");
            System.exit(64);
        }
        switch (args[0]) {
            case "scrape" -> scrape(Integer.parseInt(args[1]));
            case "readable" -> readable(args[1]);
            case "prepare-attach" -> prepareAttach(args[1]);
            case "force-gc" -> forceGc(args[1]);
            default -> {
                System.err.println("unknown mode: " + args[0]);
                System.exit(64);
            }
        }
    }

    /**
     * Stats {@code path} as this process's UID (the container's non-root user): the accessibility
     * half of the DEP-1 mounted-secrets contract, observed from inside. A path that is not a
     * regular file exits 2; an unreadable one exits 3 (the T4 refusal row's in-container twin).
     */
    private static void readable(String path) throws IOException {
        Path file = Path.of(path);
        if (!Files.isRegularFile(file)) {
            System.err.println("not a regular file: " + file);
            System.exit(2);
        }
        String perms = PosixFilePermissions.toString(Files.getPosixFilePermissions(file));
        long size = Files.size(file);
        if (!Files.isReadable(file)) {
            System.out.println("unreadable " + file + " perms=" + perms + " size=" + size);
            System.err.println("the current UID cannot read " + file + " (perms=" + perms + ")");
            System.exit(3);
        }
        System.out.println("readable " + file + " perms=" + perms + " size=" + size);
    }

    /** Raw-socket GET /metrics on the container's own loopback (no HTTP client on the runtime). */
    private static void scrape(int port) throws IOException {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(
                    ("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n"
                            + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = socket.getInputStream().read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            System.out.println(out.toString(StandardCharsets.UTF_8));
        }
    }

    /** Creates the attach-trigger file; the SIGQUIT that follows makes the target start its listener. */
    private static void prepareAttach(String pid) throws IOException {
        Path trigger = Path.of("/tmp/.attach_pid" + pid);
        Files.writeString(trigger, "");
        System.out.println("attach-trigger-created " + trigger);
    }

    /** The hand-spoken attach request: "1", "jcmd", "GC.run", two empty v1 padding arguments. */
    private static void forceGc(String pid) throws IOException, InterruptedException {
        Path socketPath = Path.of("/tmp/.java_pid" + pid);
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (!Files.exists(socketPath)) {
            if (System.nanoTime() > deadline) {
                System.err.println("no attach socket at " + socketPath
                        + " — the target's attach listener never started (SIGQUIT after prepare-attach?)");
                System.exit(2);
            }
            Thread.sleep(100);
        }
        try (SocketChannel channel = SocketChannel.open(UnixDomainSocketAddress.of(socketPath))) {
            channel.setOption(StandardSocketOptions.SO_LINGER, -1);
            ByteArrayOutputStream request = new ByteArrayOutputStream();
            writeNulString(request, "1");        // protocol version
            writeNulString(request, "jcmd");     // the jcmd command family
            writeNulString(request, "GC.run");   // the argument: force a full GC
            writeNulString(request, "");         // v1 always carries three arguments
            writeNulString(request, "");
            channel.write(ByteBuffer.wrap(request.toByteArray()));
            channel.shutdownOutput();
            ByteBuffer buf = ByteBuffer.allocate(8192);
            ByteArrayOutputStream reply = new ByteArrayOutputStream();
            int n;
            while ((n = channel.read(buf)) != -1) {
                reply.write(buf.array(), 0, n);
                buf.clear();
            }
            String text = reply.toString(StandardCharsets.UTF_8).strip();
            System.out.println("attach-reply " + text);
            String completion = text.lines().reduce((first, second) -> second).orElse("");
            if (!completion.equals("0")) {
                System.err.println("attach jcmd GC.run did not complete cleanly: <" + text + ">");
                System.exit(3);
            }
        }
    }

    private static void writeNulString(ByteArrayOutputStream out, String s) {
        out.writeBytes(s.getBytes(StandardCharsets.UTF_8));
        out.write(0);
    }
}
