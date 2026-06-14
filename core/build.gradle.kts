/*
 * core - crypto + key management library.
 *
 * Deliberately free of any socket/transport/CLI code so it stays reusable.
 * It owns: the Argon2id master-key derivation, AES-256-GCM envelope format,
 * the MasterKeyProvider seam, the KMS operations, and the JSON wire DTOs.
 */

plugins {
    `java-library`
}

dependencies {
    // Argon2id KDF + a reliable crypto provider.
    api(libs.bouncycastle)
    // Wire-protocol DTOs are (de)serialized with Jackson; shared by server + client.
    api(libs.jackson.databind)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
