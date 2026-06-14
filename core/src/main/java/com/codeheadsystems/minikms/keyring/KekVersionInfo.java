package com.codeheadsystems.minikms.keyring;

/**
 * Metadata about a single KEK version, with no key material. Returned by the
 * control plane (e.g. list/rotate) so operators can inspect the keyring safely.
 *
 * @param version           the version number within its group.
 * @param status            its lifecycle status.
 * @param createdAtEpochSec creation time (epoch seconds).
 */
public record KekVersionInfo(long version, KeyVersionStatus status, long createdAtEpochSec) {
}
