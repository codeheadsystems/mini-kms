/*
 * Multi-module build for mini-kms, a small single-machine Key Management Service.
 *
 *   core   - crypto + key management library (no I/O, no transport)
 *   server - the socket daemon (TCP loopback + Unix domain socket); depends on core
 *   client - a CLI client + reusable client library; depends on core
 */

plugins {
    // Apply the foojay-resolver plugin to allow automatic download of JDKs.
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "mini-kms"

include("core")
include("server")
include("client")
