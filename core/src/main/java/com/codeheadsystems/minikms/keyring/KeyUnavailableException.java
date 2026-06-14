package com.codeheadsystems.minikms.keyring;

/**
 * Thrown on the data plane when a ciphertext references a KEK version that cannot
 * decrypt it — unknown group/version, or a version that is disabled or destroyed.
 *
 * <p>Like an AEAD failure, this is surfaced to clients as a generic
 * decryption failure so the protocol does not reveal keyring internals.
 */
public class KeyUnavailableException extends RuntimeException {

  /** @param message a generic, non-revealing description. */
  public KeyUnavailableException(final String message) {
    super(message);
  }
}
