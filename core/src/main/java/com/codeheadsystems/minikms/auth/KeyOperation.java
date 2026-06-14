package com.codeheadsystems.minikms.auth;

/**
 * The data-plane operations subject to per-key-group authorization.
 *
 * <p>Used by {@link KeyAuthorizationPolicy} so a future per-client policy can,
 * for example, allow a client to {@code DECRYPT} with a group but not
 * {@code ENCRYPT} new data under it.
 */
public enum KeyOperation {
  /** GenerateDataKey against a group. */
  GENERATE_DATA_KEY,
  /** Encrypt under a group. */
  ENCRYPT,
  /** Decrypt a blob (group taken from the blob). */
  DECRYPT,
  /** Re-encrypt to a destination group. */
  RE_ENCRYPT
}
