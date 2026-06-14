package com.codeheadsystems.minikms.kms;

import com.codeheadsystems.minikms.keyring.KekId;

/**
 * DATA PLANE seam — the per-request cryptographic operations, exposing no raw
 * key material.
 *
 * <p>This is the only crypto surface the request handler touches for data-plane
 * traffic ({@code GenerateDataKey} / {@code Encrypt} / {@code Decrypt} /
 * {@code ReEncrypt}). Wrapping and direct encryption target a named <b>key
 * group</b> and always use that group's <b>active version</b>; the resulting blob
 * records its {@link KekId}, so unwrap/decrypt can select the right version
 * automatically — even after the group has been rotated.
 *
 * <p>The local implementation is
 * {@link com.codeheadsystems.minikms.keyring.LocalKeyring}. A future
 * {@code RemoteMasterKeyProvider} delegating wrap/unwrap to a remote KMS can
 * implement this same interface with no change to the request handler.
 */
public interface MasterKeyProvider extends AutoCloseable {

  /** The key group used when a request does not name one. */
  String DEFAULT_KEY_GROUP = "default";

  /**
   * Wrap a data key under the active version of a key group.
   *
   * @param keyGroupId the target group (use {@link #DEFAULT_KEY_GROUP} if unspecified).
   * @param dek        the plaintext data key.
   * @param aad        optional encryption context; may be {@code null}.
   * @return the serialized {@link com.codeheadsystems.minikms.keyring.KekEnvelope}.
   */
  byte[] wrap(String keyGroupId, byte[] dek, byte[] aad);

  /**
   * Unwrap a wrapped data key. The key group + version are read from the blob.
   *
   * @param wrapped the serialized wrapped data key.
   * @param aad     the same context supplied to {@link #wrap}; may be {@code null}.
   * @return the plaintext data key.
   */
  byte[] unwrap(byte[] wrapped, byte[] aad);

  /**
   * Encrypt a small blob directly under the active version of a key group.
   *
   * @param keyGroupId the target group.
   * @param plaintext  the data to encrypt.
   * @param aad        optional encryption context; may be {@code null}.
   * @return the serialized ciphertext envelope.
   */
  byte[] encrypt(String keyGroupId, byte[] plaintext, byte[] aad);

  /**
   * Decrypt a blob. The key group + version are read from the blob.
   *
   * @param ciphertext the serialized ciphertext envelope.
   * @param aad        the same context supplied to {@link #encrypt}; may be {@code null}.
   * @return the recovered plaintext.
   */
  byte[] decrypt(byte[] ciphertext, byte[] aad);

  /**
   * Read which key wrapped a blob, without decrypting it. Used to authorize
   * access (which key group is being touched) before attempting decryption.
   *
   * @param blob a serialized client-facing ciphertext/wrapped key.
   * @return the {@link KekId} the blob was produced under.
   */
  KekId keyIdOf(byte[] blob);

  /** Release held secrets (zero in-memory keys). */
  @Override
  void close();
}
