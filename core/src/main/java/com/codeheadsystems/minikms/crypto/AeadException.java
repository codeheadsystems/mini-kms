package com.codeheadsystems.minikms.crypto;

/**
 * Thrown when an AES-GCM decryption fails its authentication check.
 *
 * <p>This deliberately carries no detail about <em>why</em> authentication
 * failed (wrong key, wrong AAD, or a tampered/truncated ciphertext all look the
 * same) so that callers and logs cannot be used as a decryption oracle.
 */
public class AeadException extends RuntimeException {

  /**
   * Create the exception.
   *
   * @param message a generic, non-revealing description of the failure.
   */
  public AeadException(final String message) {
    super(message);
  }
}
