package com.codeheadsystems.minikms.keyring;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * Persisted form of a key group: its id, the active version pointer, and all its
 * versions.
 *
 * @param id            group name.
 * @param activeVersion version used for new encryption.
 * @param versions      all versions.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KeyGroupMetadata(String id, long activeVersion, List<KekVersionMetadata> versions) {
}
