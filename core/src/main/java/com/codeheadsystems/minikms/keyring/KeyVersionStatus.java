package com.codeheadsystems.minikms.keyring;

/**
 * Lifecycle state of a single KEK version within a key group.
 *
 * <p>At most one version per group is {@link #ACTIVE} at a time; rotation makes a
 * new version active and demotes the previous one to {@link #ENABLED}.
 */
public enum KeyVersionStatus {

  /** Used for new wrap/encrypt operations <em>and</em> decrypt. Exactly one per group. */
  ACTIVE,

  /** No longer used for new encryption, but still valid for decrypt/unwrap of old data. */
  ENABLED,

  /** Temporarily unusable for any operation; can be re-enabled. */
  DISABLED,

  /** Key material has been destroyed; any data wrapped under it is permanently unrecoverable. */
  DESTROYED;

  /** @return whether this version may decrypt/unwrap existing ciphertexts. */
  public boolean canDecrypt() {
    return this == ACTIVE || this == ENABLED;
  }

  /** @return whether this version may be used to encrypt/wrap new data. */
  public boolean canEncrypt() {
    return this == ACTIVE;
  }
}
