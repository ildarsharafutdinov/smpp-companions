// OBS-013: the proxy module's RUNTIME classpath must NOT carry a web stack or Reactor:
// no spring-boot-starter-web/-tomcat/-webflux/-actuator, no spring-web*/-webmvc/-webflux/-websocket,
// no Reactor (io.projectreactor*), no embedded Tomcat. This is the gate OBS-043 exercises.
// Applied to: the `proxy` module.
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

// A Gradle resolution gate by design (NOT ArchUnit): ArchUnit can't express Maven group bans or see
// classless aggregator POMs (e.g. spring-boot-starter-web). SEC-090 owns the class-dep rule ArchUnit
// IS good at.

// Any artifact from these GROUPS is forbidden outright.
val forbiddenGroups: Set<String> = setOf(
    "io.projectreactor",
    "io.projectreactor.netty",
    "org.eclipse.jetty",      // AD-16: no embedded server — Jetty is the other Spring Boot web runtime
    "io.undertow",            // AD-16: no embedded server — Undertow likewise
    "org.glassfish.jersey"    // AD-16: no embedded server — Jersey servlet / JAX-RS stack
)

// These specific GROUP:NAME coordinates are forbidden (the proxy legitimately uses the non-web
// `spring-boot-starter`, so the whole org.springframework.boot group is NOT banned).
// Covers every Spring Boot web-runtime starter so swapping Tomcat for Jetty/Undertow/Jersey can't
// sneak an embedded server past the gate.
val forbiddenArtifacts: Set<String> = setOf(
    "org.springframework.boot:spring-boot-starter-web",
    "org.springframework.boot:spring-boot-starter-tomcat",
    "org.springframework.boot:spring-boot-starter-jetty",
    "org.springframework.boot:spring-boot-starter-undertow",
    "org.springframework.boot:spring-boot-starter-jersey",
    "org.springframework.boot:spring-boot-starter-webflux",
    "org.springframework.boot:spring-boot-starter-actuator",
    "org.springframework:spring-web",
    "org.springframework:spring-webmvc",
    "org.springframework:spring-webflux",
    "org.springframework:spring-websocket",
    "org.apache.tomcat.embed:tomcat-embed-core",      // AD-16 server (EL impl tomcat-embed-el is allowed)
    "org.apache.tomcat.embed:tomcat-embed-websocket"
)

tasks.register("enforceRuntimeAllowlist") {
    group = "verification"
    description = "OBS-013: fail if proxy runtime classpath contains a forbidden web-stack / reactor dep."

    doLast {
        val resolved = project.configurations.named("runtimeClasspath").get()
            .incoming.resolutionResult.allComponents
            .mapNotNull { it.id }
            .filterIsInstance<ModuleComponentIdentifier>()

        val offenders = resolved.mapNotNull { id ->
            val ga = "${id.group}:${id.module}"
            when {
                id.group in forbiddenGroups -> "$ga:${id.version} (forbidden group)"
                ga in forbiddenArtifacts -> "$ga:${id.version} (forbidden artifact)"
                else -> null
            }
        }.sorted()

        check(offenders.isEmpty()) {
            "OBS-013: proxy runtime classpath contains a forbidden web-stack / reactor dependency " +
                    "(AD-16: no embedded web server, no WebFlux/Reactor):\n  " +
                    offenders.joinToString("\n  ")
        }
        logger.lifecycle("OBS-013 OK — proxy runtime classpath has no web stack / reactor.")
    }
}

tasks.named("check") { dependsOn("enforceRuntimeAllowlist") }
