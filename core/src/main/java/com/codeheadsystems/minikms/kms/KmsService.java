package com.codeheadsystems.minikms.kms;

import com.codeheadsystems.minikms.crypto.AesGcm;
import com.codeheadsystems.minikms.keyring.KekId;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * DATA PLANE — the KMS operations, AWS-KMS-style, implemented purely over a
 * {@link MasterKeyProvider}.
 *
 * <p>Transport-agnostic: no sockets, JSON, or auth here. Every operation targets
 * a named key group (defaulting to {@link MasterKeyProvider#DEFAULT_KEY_GROUP});
 * the provider always uses that group's active version and records the
 * {@link com.codeheadsystems.minikms.keyring.KekId} in each blob so decryption
 * after rotation still works.
 */
public class KmsService {

  private final MasterKeyProvider masterKeyProvider;
  private final SecureRandom secureRandom;

  /** @param masterKeyProvider the data-plane seam. */
  public KmsService(final MasterKeyProvider masterKeyProvider) {
    this(masterKeyProvider, new SecureRandom());
  }

  /**
   * @param masterKeyProvider the data-plane seam.
   * @param secureRandom      randomness for new data keys.
   */
  public KmsService(final MasterKeyProvider masterKeyProvider, final SecureRandom secureRandom) {
    this.masterKeyProvider = masterKeyProvider;
    this.secureRandom = secureRandom;
  }

  /**
   * Generate a new 256-bit data key, wrapped under a key group's active version.
   *
   * @param keyGroupId target group (null/blank → default).
   * @param aad        optional encryption context; may be {@code null}.
   * @return plaintext + wrapped DEK.
   */
  public DataKey generateDataKey(final String keyGroupId, final byte[] aad) {
    final byte[] dek = new byte[AesGcm.KEY_LENGTH_BYTES];
    secureRandom.nextBytes(dek);
    final byte[] wrapped = masterKeyProvider.wrap(keyGroupId, dek, aad);
    return new DataKey(dek, wrapped);
  }

  /**
   * Encrypt a small blob directly under a key group's active version.
   *
   * @param keyGroupId target group (null/blank → default).
   * @param plaintext  the data to encrypt.
   * @param aad        optional encryption context; may be {@code null}.
   * @return the serialized ciphertext.
   */
  public byte[] encrypt(final String keyGroupId, final byte[] plaintext, final byte[] aad) {
    return masterKeyProvider.encrypt(keyGroupId, plaintext, aad);
  }

  /**
   * Decrypt a blob or unwrap a data key (the key + version are read from the blob).
   *
   * @param ciphertext the serialized ciphertext or wrapped DEK.
   * @param aad        the same context used to produce it; may be {@code null}.
   * @return the recovered plaintext.
   */
  public byte[] decrypt(final byte[] ciphertext, final byte[] aad) {
    return masterKeyProvider.decrypt(ciphertext, aad);
  }

  /**
   * Re-encrypt a blob to a (possibly different) key group's active version without
   * exposing the plaintext outside the server. The natural companion to rotation:
   * migrate old ciphertexts onto the newest key.
   *
   * @param ciphertext      the existing serialized ciphertext/wrapped key.
   * @param destKeyGroupId  the destination group (null/blank → default).
   * @param aad             the encryption context (used for both decrypt and re-encrypt).
   * @return the re-encrypted blob under the destination group's active version.
   */
  public byte[] reEncrypt(final byte[] ciphertext, final String destKeyGroupId, final byte[] aad) {
    final byte[] plaintext = masterKeyProvider.decrypt(ciphertext, aad);
    try {
      return masterKeyProvider.encrypt(destKeyGroupId, plaintext, aad);
    } finally {
      Arrays.fill(plaintext, (byte) 0);
    }
  }

  /**
   * Read which key wrapped a blob (without decrypting), so callers can authorize
   * access to the right key group before attempting a decrypt.
   *
   * @param ciphertext a serialized ciphertext/wrapped key.
   * @return the {@link KekId} it was produced under.
   */
  public KekId keyIdOf(final byte[] ciphertext) {
    return masterKeyProvider.keyIdOf(ciphertext);
  }
}
