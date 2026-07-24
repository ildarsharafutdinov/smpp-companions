// Root build. JDK 25 toolchain + --enable-preview conventions live in buildSrc
// (smpp.java-conventions); each module applies them. This file only owns the OWASP dependency-check
// plugin VERSION (SEC-091 CI lane), which the proxy module applies and configures.

plugins {
    id("org.owasp.dependencycheck") version "12.2.2" apply false
}

allprojects {
    group = "smpp.companions"
    version = "0.1.0-SNAPSHOT"
}
