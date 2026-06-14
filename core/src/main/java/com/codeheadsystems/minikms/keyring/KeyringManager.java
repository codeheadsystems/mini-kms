package com.codeheadsystems.minikms.keyring;

import java.util.List;

/**
 * CONTROL PLANE seam — administrative management of the keyring.
 *
 * <p>These operations create and rotate keys; they do not encrypt or decrypt
 * caller data. They are kept on a separate interface from the data-plane
 * {@link com.codeheadsystems.minikms.kms.MasterKeyProvider} so the two planes are
 * authorized and reasoned about independently, and so a future remote
 * implementation can manage its keyring via its own control API.
 *
 * <p>Invariants enforced by implementations:
 * <ul>
 *   <li>each group has exactly one {@link KeyVersionStatus#ACTIVE} version;</li>
 *   <li>{@link #rotateKeyGroup} mints a new active version and demotes the old to
 *       {@link KeyVersionStatus#ENABLED}, so prior ciphertexts still decrypt;</li>
 *   <li>the active version cannot be disabled or destroyed (rotate first).</li>
 * </ul>
 *
 * <p>Note: root/passphrase rotation is intentionally <em>not</em> here — it is an
 * offline operation (see {@code RootKeyRotation}) that never sends a passphrase
 * over the network.
 */
public interface KeyringManager {

  /**
   * Create a new, empty key group with an initial active version (1).
   *
   * @param keyGroupId the new group's name; must not already exist.
   * @return info about the created group.
   */
  KeyGroupInfo createKeyGroup(String keyGroupId);

  /**
   * Rotate a key group: create a new active version, demote the previous active
   * to {@link KeyVersionStatus#ENABLED}.
   *
   * @param keyGroupId the group to rotate.
   * @return info about the group after rotation.
   */
  KeyGroupInfo rotateKeyGroup(String keyGroupId);

  /** @return info for every key group (no key material). */
  List<KeyGroupInfo> listKeyGroups();

  /**
   * Disable a non-active version (it can no longer decrypt until re-enabled).
   *
   * @param keyGroupId the group.
   * @param version    the version to disable.
   */
  void disableVersion(String keyGroupId, long version);

  /**
   * Re-enable a previously disabled version.
   *
   * @param keyGroupId the group.
   * @param version    the version to enable.
   */
  void enableVersion(String keyGroupId, long version);

  /**
   * Destroy a non-active version's key material. <b>Irreversible:</b> any data
   * wrapped under it becomes permanently unrecoverable.
   *
   * @param keyGroupId the group.
   * @param version    the version to destroy.
   */
  void destroyVersion(String keyGroupId, long version);
}
