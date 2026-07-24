pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    // Single source of truth for repositories; module build scripts must not declare their own.
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

plugins {
    // Toolchain auto-PROVISIONING resolver (Gradle 9 line). Auto-DETECTION is built into Gradle 9
    // and will find the local Temurin 25.0.3 with zero config; this plugin only provisions a JDK
    // when no local match exists (CI / fresh machines). 1.0.0 targets Gradle 9 (the 0.x line is <=8).
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "smpp-companions"

include("codec", "proxy")
