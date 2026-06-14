package com.codeheadsystems.minikms.kms;

/**
 * The result of a {@code GenerateDataKey} operation: a fresh data encryption key
 * (DEK) returned both in plaintext and wrapped under the master key.
 *
 * <p>The envelope-encryption pattern: a client uses {@code plaintext} to encrypt
 * its data locally (bulk encryption is fast and stays off the KMS), stores only
 * {@code wrapped} next to the ciphertext, and discards the plaintext DEK. Later
 * it sends {@code wrapped} back to the KMS to recover the plaintext DEK and
 * decrypt. The master key never leaves the server.
 *
 * @param plaintext the raw 256-bit DEK; the caller should use it then discard/zero it.
 * @param wrapped   the DEK encrypted under the master key (a serialized envelope).
 */
public record DataKey(byte[] plaintext, byte[] wrapped) {

  /** Defensive copies in. */
  public DataKey {
    plaintext = plaintext.clone();
    wrapped = wrapped.clone();
  }

  @Override
  public byte[] plaintext() {
    return plaintext.clone();
  }

  @Override
  public byte[] wrapped() {
    return wrapped.clone();
  }
}
