package com.codeheadsystems.minikms.protocol;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * Wire view of a key group (no key material). Returned in control-plane responses.
 *
 * @param keyId         the group name.
 * @param activeVersion the version used for new encryption.
 * @param versions      all versions, oldest first.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KeyGroupView(String keyId, long activeVersion, List<KekVersionView> versions) {
}
