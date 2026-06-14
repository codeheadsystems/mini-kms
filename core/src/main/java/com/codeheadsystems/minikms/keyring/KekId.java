package com.codeheadsystems.minikms.keyring;

/**
 * Identifies the exact key-encryption key that wrapped a ciphertext:
 * the <b>key group</b> plus the <b>version</b> within that group.
 *
 * <p>This is the {@code kek_id} carried inside every client-facing ciphertext. It
 * is intentionally human-readable rather than opaque — a stored blob literally
 * records "this was wrapped by group {@code billing}, version {@code 2}", which
 * is what makes rotation safe: after rotating, old ciphertexts still name the old
 * version and can still be decrypted.
 *
 * <p>The pairing mirrors a real KMS: the group is the addressable key (AWS
 * "KeyId" / GCP "CryptoKey"), and the version is a single rotation of its key
 * material (AWS "key material version" / GCP "CryptoKeyVersion").
 *
 * @param keyGroupId the key group name (e.g. {@code "default"}, {@code "billing"}).
 * @param version    the monotonically increasing version within that group (starts at 1).
 */
public record KekId(String keyGroupId, long version) {

  /** Max key-group id length in bytes; bounds the envelope header. */
  public static final int MAX_GROUP_ID_BYTES = 255;

  /** Validate. */
  public KekId {
    if (keyGroupId == null || keyGroupId.isBlank()) {
      throw new IllegalArgumentException("keyGroupId must not be blank");
    }
    if (keyGroupId.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_GROUP_ID_BYTES) {
      throw new IllegalArgumentException("keyGroupId too long (max " + MAX_GROUP_ID_BYTES + " bytes)");
    }
    if (version < 1) {
      throw new IllegalArgumentException("version must be >= 1");
    }
  }

  @Override
  public String toString() {
    return keyGroupId + ":v" + version;
  }
}
