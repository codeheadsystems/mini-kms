package com.codeheadsystems.minikms.protocol;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Wire view of one KEK version (no key material). Returned in control-plane
 * responses such as {@code ListKeyGroups} and {@code RotateKeyGroup}.
 *
 * @param version           version number.
 * @param status            lifecycle status ({@code ACTIVE}/{@code ENABLED}/{@code DISABLED}/{@code DESTROYED}).
 * @param createdAtEpochSec creation time (epoch seconds).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KekVersionView(long version, String status, long createdAtEpochSec) {
}
