/*
 * client - reusable client library plus two CLIs.
 *
 *   KmsClient   - the embeddable library (open a socket, send requests, parse responses).
 *   ClientMain  - the DATA-PLANE CLI ("client"): generate/encrypt/decrypt/reencrypt + file envelopes.
 *   KeyringAdminMain - the CONTROL-PLANE CLI ("kms-admin"): rotate/create/list/disable/destroy keys,
 *                      and offline passphrase rotation.
 *
 * Depends on core for the shared protocol DTOs, the envelope format used to
 * encrypt files locally, and (for offline passphrase rotation) the keyring.
 */

plugins {
    application
}

dependencies {
    implementation(project(":core"))

    testImplementation(project(":core"))
    testImplementation(project(":server"))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    // The data-plane CLI is the primary entry point.
    mainClass = "com.codeheadsystems.minikms.client.ClientMain"
}

// A second launcher script for the control-plane (admin) CLI, bundled in the
// same distribution as `bin/kms-admin` alongside `bin/client`.
val adminStartScripts = tasks.register<CreateStartScripts>("adminStartScripts") {
    applicationName = "kms-admin"
    mainClass = "com.codeheadsystems.minikms.client.KeyringAdminMain"
    outputDir = layout.buildDirectory.dir("adminScripts").get().asFile
    classpath = tasks.named<Jar>("jar").get().outputs.files + configurations.runtimeClasspath.get()
}

tasks.named<org.gradle.jvm.application.tasks.CreateStartScripts>("startScripts") {
    dependsOn(adminStartScripts)
}

distributions {
    named("main") {
        contents {
            from(adminStartScripts) {
                into("bin")
            }
        }
    }
}
