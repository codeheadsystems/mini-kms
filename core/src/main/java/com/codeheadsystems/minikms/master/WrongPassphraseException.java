package com.codeheadsystems.minikms.master;

/**
 * Thrown during startup when the supplied passphrase does not match the one the
 * keystore was initialized with (the verification token fails to decrypt).
 *
 * <p>The server treats this as fatal and refuses to start serving.
 */
public class WrongPassphraseException extends RuntimeException {

  /**
   * Create the exception.
   *
   * @param message a generic description (never echoes the passphrase).
   */
  public WrongPassphraseException(final String message) {
    super(message);
  }
}
