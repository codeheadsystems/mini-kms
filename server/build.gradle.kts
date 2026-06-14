/*
 * server - the socket daemon.
 *
 * Binds a loopback-only TCP socket and a Unix domain socket, speaks the
 * newline-delimited JSON protocol, authenticates with a shared API token,
 * and delegates all crypto to core. Has a runnable main entry point.
 */

plugins {
    application
}

dependencies {
    implementation(project(":core"))

    testImplementation(project(":core"))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass = "com.codeheadsystems.minikms.server.ServerMain"
}
