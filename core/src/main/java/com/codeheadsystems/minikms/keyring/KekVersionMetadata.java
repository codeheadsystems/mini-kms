package com.codeheadsystems.minikms.keyring;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Persisted form of one KEK version: its number, status, creation time, and the
 * KEK material <em>wrapped under the root key</em>. The plaintext KEK is never
 * stored. When a version is destroyed, {@code wrappedKekBase64} is cleared.
 *
 * @param version          version number within the group.
 * @param status           lifecycle status name.
 * @param createdAtEpochSec creation time (epoch seconds).
 * @param wrappedKekBase64 the KEK encrypted under the root key (base64), or {@code null} if destroyed.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KekVersionMetadata(
    long version,
    String status,
    long createdAtEpochSec,
    String wrappedKekBase64) {
}
