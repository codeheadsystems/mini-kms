package com.codeheadsystems.minikms.kms;

import com.codeheadsystems.minikms.auth.ApiTokenAuthenticator;
import com.codeheadsystems.minikms.auth.KeyAuthorizationPolicy;
import com.codeheadsystems.minikms.auth.KeyOperation;
import com.codeheadsystems.minikms.auth.Principal;
import com.codeheadsystems.minikms.crypto.AeadException;
import com.codeheadsystems.minikms.keyring.KeyGroupInfo;
import com.codeheadsystems.minikms.keyring.KeyUnavailableException;
import com.codeheadsystems.minikms.keyring.KeyringException;
import com.codeheadsystems.minikms.keyring.KeyringManager;
import com.codeheadsystems.minikms.protocol.ErrorCode;
import com.codeheadsystems.minikms.protocol.KekVersionView;
import com.codeheadsystems.minikms.protocol.KeyGroupView;
import com.codeheadsystems.minikms.protocol.KmsRequest;
import com.codeheadsystems.minikms.protocol.KmsResponse;
import com.codeheadsystems.minikms.protocol.RequestPlane;
import com.codeheadsystems.minikms.protocol.RequestType;
import java.util.Base64;
import java.util.List;

/**
 * Turns a parsed {@link KmsRequest} into a {@link KmsResponse}, routing the two
 * planes explicitly:
 *
 * <ul>
 *   <li><b>DATA PLANE</b> ({@code GenerateDataKey}/{@code Encrypt}/{@code Decrypt}/
 *       {@code ReEncrypt}/{@code Health}) is authenticated with the <b>API token</b>
 *       and authorized per key group by the {@link KeyAuthorizationPolicy}.</li>
 *   <li><b>CONTROL PLANE</b> ({@code Create/Rotate/List/Disable/Enable/Destroy})
 *       is authenticated with the <b>admin token</b>.</li>
 * </ul>
 *
 * <p>Transport-agnostic and the documented seam: it depends only on a
 * {@link KmsService} (data) and a {@link KeyringManager} (control), so a remote
 * master-key/keyring implementation drops in unchanged. It never throws on bad
 * input — every failure becomes a structured error response, and crypto/keyring
 * unavailability is flattened to {@link ErrorCode#DECRYPTION_FAILED} to avoid an
 * oracle. No secret material ever appears in a message.
 */
public class KmsRequestHandler {

  private final KmsService kmsService;
  private final KeyringManager keyringManager;
  private final ApiTokenAuthenticator dataAuthenticator;
  private final ApiTokenAuthenticator adminAuthenticator;
  private final KeyAuthorizationPolicy authorizationPolicy;

  /**
   * @param kmsService          data-plane operations.
   * @param keyringManager      control-plane operations.
   * @param dataAuthenticator   validates the API token (data plane).
   * @param adminAuthenticator  validates the admin token (control plane).
   * @param authorizationPolicy per-key-group authorization for data-plane ops.
   */
  public KmsRequestHandler(final KmsService kmsService, final KeyringManager keyringManager,
                           final ApiTokenAuthenticator dataAuthenticator,
                           final ApiTokenAuthenticator adminAuthenticator,
                           final KeyAuthorizationPolicy authorizationPolicy) {
    this.kmsService = kmsService;
    this.keyringManager = keyringManager;
    this.dataAuthenticator = dataAuthenticator;
    this.adminAuthenticator = adminAuthenticator;
    this.authorizationPolicy = authorizationPolicy;
  }

  /**
   * Handle one request.
   *
   * @param request the parsed request (may be {@code null}).
   * @return the response to send back.
   */
  public KmsResponse handle(final KmsRequest request) {
    if (request == null || request.type() == null) {
      return KmsResponse.error(ErrorCode.INVALID_REQUEST, "missing or unknown request type");
    }
    final RequestType type = request.type();

    // Authenticate against the token for this plane.
    final boolean control = type.plane() == RequestPlane.CONTROL;
    final ApiTokenAuthenticator authenticator = control ? adminAuthenticator : dataAuthenticator;
    if (!authenticator.isValid(request.token())) {
      return KmsResponse.error(ErrorCode.AUTH_FAILED, control ? "invalid admin token" : "invalid API token");
    }
    final Principal principal = control ? Principal.SHARED_ADMIN : Principal.SHARED_DATA_CLIENT;

    try {
      return switch (type) {
        // ---- DATA PLANE ----
        case HEALTH -> KmsResponse.healthy();
        case GENERATE_DATA_KEY -> generateDataKey(request, principal);
        case ENCRYPT -> encrypt(request, principal);
        case DECRYPT -> decrypt(request, principal);
        case RE_ENCRYPT -> reEncrypt(request, principal);
        // ---- CONTROL PLANE ----
        case CREATE_KEY_GROUP -> KmsResponse.group(view(keyringManager.createKeyGroup(requireKeyId(request))));
        case ROTATE_KEY_GROUP -> KmsResponse.group(view(keyringManager.rotateKeyGroup(requireKeyId(request))));
        case LIST_KEY_GROUPS -> KmsResponse.groups(views(keyringManager.listKeyGroups()));
        case DISABLE_VERSION -> versionOp(request, "disabled");
        case ENABLE_VERSION -> versionOp(request, "enabled");
        case DESTROY_VERSION -> versionOp(request, "destroyed");
      };
    } catch (final AeadException | KeyUnavailableException e) {
      return KmsResponse.error(ErrorCode.DECRYPTION_FAILED, "decryption failed");
    } catch (final KeyringException e) {
      return KmsResponse.error(ErrorCode.INVALID_REQUEST, e.getMessage());
    } catch (final IllegalArgumentException e) {
      return KmsResponse.error(ErrorCode.INVALID_REQUEST, e.getMessage());
    } catch (final RuntimeException e) {
      return KmsResponse.error(ErrorCode.INTERNAL_ERROR, "internal error");
    }
  }

  // ---- DATA PLANE handlers ----

  private KmsResponse generateDataKey(final KmsRequest request, final Principal principal) {
    final String group = groupOrDefault(request.keyId());
    final KmsResponse denied = authorize(principal, group, KeyOperation.GENERATE_DATA_KEY);
    if (denied != null) {
      return denied;
    }
    final DataKey dataKey = kmsService.generateDataKey(group, decodeOptional(request.aad()));
    return KmsResponse.dataKey(
        Base64.getEncoder().encodeToString(dataKey.plaintext()),
        Base64.getEncoder().encodeToString(dataKey.wrapped()));
  }

  private KmsResponse encrypt(final KmsRequest request, final Principal principal) {
    final String group = groupOrDefault(request.keyId());
    final KmsResponse denied = authorize(principal, group, KeyOperation.ENCRYPT);
    if (denied != null) {
      return denied;
    }
    final byte[] plaintext = decodeRequired(request.plaintext(), "plaintext");
    final byte[] ciphertext = kmsService.encrypt(group, plaintext, decodeOptional(request.aad()));
    return KmsResponse.encrypted(Base64.getEncoder().encodeToString(ciphertext));
  }

  private KmsResponse decrypt(final KmsRequest request, final Principal principal) {
    final byte[] ciphertext = decodeRequired(request.ciphertext(), "ciphertext");
    final byte[] aad = decodeOptional(request.aad());
    final String sourceGroup = kmsService.keyIdOf(ciphertext).keyGroupId();
    final KmsResponse denied = authorize(principal, sourceGroup, KeyOperation.DECRYPT);
    if (denied != null) {
      return denied;
    }
    return KmsResponse.decrypted(Base64.getEncoder().encodeToString(kmsService.decrypt(ciphertext, aad)));
  }

  private KmsResponse reEncrypt(final KmsRequest request, final Principal principal) {
    final byte[] ciphertext = decodeRequired(request.ciphertext(), "ciphertext");
    final byte[] aad = decodeOptional(request.aad());
    final String destGroup = groupOrDefault(request.keyId());
    // Must be allowed to decrypt the source group AND encrypt under the destination group.
    final KmsResponse deniedSrc = authorize(principal, kmsService.keyIdOf(ciphertext).keyGroupId(),
        KeyOperation.DECRYPT);
    if (deniedSrc != null) {
      return deniedSrc;
    }
    final KmsResponse deniedDest = authorize(principal, destGroup, KeyOperation.RE_ENCRYPT);
    if (deniedDest != null) {
      return deniedDest;
    }
    return KmsResponse.encrypted(
        Base64.getEncoder().encodeToString(kmsService.reEncrypt(ciphertext, destGroup, aad)));
  }

  // ---- CONTROL PLANE helpers ----

  private KmsResponse versionOp(final KmsRequest request, final String verbPast) {
    final String keyId = requireKeyId(request);
    final long version = requireVersion(request);
    switch (request.type()) {
      case DISABLE_VERSION -> keyringManager.disableVersion(keyId, version);
      case ENABLE_VERSION -> keyringManager.enableVersion(keyId, version);
      case DESTROY_VERSION -> keyringManager.destroyVersion(keyId, version);
      default -> throw new IllegalStateException("not a version op: " + request.type());
    }
    return KmsResponse.ok(keyId + " v" + version + " " + verbPast);
  }

  // ---- shared helpers ----

  /** @return an UNAUTHORIZED response if denied, or {@code null} if allowed. */
  private KmsResponse authorize(final Principal principal, final String group, final KeyOperation op) {
    if (!authorizationPolicy.isAllowed(principal, group, op)) {
      return KmsResponse.error(ErrorCode.UNAUTHORIZED, "not permitted for key group " + group);
    }
    return null;
  }

  private static String groupOrDefault(final String keyId) {
    return keyId == null || keyId.isBlank() ? MasterKeyProvider.DEFAULT_KEY_GROUP : keyId;
  }

  private static String requireKeyId(final KmsRequest request) {
    if (request.keyId() == null || request.keyId().isBlank()) {
      throw new IllegalArgumentException("keyId is required");
    }
    return request.keyId();
  }

  private static long requireVersion(final KmsRequest request) {
    if (request.version() == null) {
      throw new IllegalArgumentException("version is required");
    }
    return request.version();
  }

  private static KeyGroupView view(final KeyGroupInfo info) {
    final List<KekVersionView> versions = info.versions().stream()
        .map(v -> new KekVersionView(v.version(), v.status().name(), v.createdAtEpochSec()))
        .toList();
    return new KeyGroupView(info.keyGroupId(), info.activeVersion(), versions);
  }

  private static List<KeyGroupView> views(final List<KeyGroupInfo> infos) {
    return infos.stream().map(KmsRequestHandler::view).toList();
  }

  private static byte[] decodeRequired(final String base64, final String field) {
    if (base64 == null) {
      throw new IllegalArgumentException("missing required field: " + field);
    }
    return decode(base64, field);
  }

  private static byte[] decodeOptional(final String base64) {
    return base64 == null ? null : decode(base64, "aad");
  }

  private static byte[] decode(final String base64, final String field) {
    try {
      return Base64.getDecoder().decode(base64);
    } catch (final IllegalArgumentException e) {
      throw new IllegalArgumentException("field '" + field + "' is not valid base64");
    }
  }
}
