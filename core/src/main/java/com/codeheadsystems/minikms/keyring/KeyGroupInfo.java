package com.codeheadsystems.minikms.keyring;

import java.util.List;

/**
 * Metadata about a key group, with no key material. Returned by the control
 * plane so operators can see each group's active version and version history.
 *
 * @param keyGroupId    the group name.
 * @param activeVersion the version currently used for new encryption.
 * @param versions      all versions in the group, oldest first.
 */
public record KeyGroupInfo(String keyGroupId, long activeVersion, List<KekVersionInfo> versions) {

  /** Defensive copy. */
  public KeyGroupInfo {
    versions = List.copyOf(versions);
  }
}
