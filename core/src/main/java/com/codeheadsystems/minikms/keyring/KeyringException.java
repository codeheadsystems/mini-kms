package com.codeheadsystems.minikms.keyring;

/**
 * Thrown by control-plane operations for invalid requests, e.g. creating a group
 * that already exists, referencing an unknown group/version, or trying to
 * disable/destroy the active version.
 */
public class KeyringException extends RuntimeException {

  /** @param message a description safe to return to an authorized operator. */
  public KeyringException(final String message) {
    super(message);
  }
}
