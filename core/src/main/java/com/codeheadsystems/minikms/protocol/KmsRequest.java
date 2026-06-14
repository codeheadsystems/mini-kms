package com.codeheadsystems.minikms.protocol;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A single request object, one per line of newline-delimited JSON.
 *
 * <p>Binary fields are base64-encoded strings. Required fields by {@link #type}:
 *
 * <p><b>Data plane</b> (uses the API token):
 * <ul>
 *   <li>{@code GenerateDataKey}: optional {@link #keyId}, optional {@link #aad}.</li>
 *   <li>{@code Encrypt}: {@link #plaintext}; optional {@link #keyId}, {@link #aad}.</li>
 *   <li>{@code Decrypt}: {@link #ciphertext}; optional {@link #aad}.</li>
 *   <li>{@code ReEncrypt}: {@link #ciphertext} + destination {@link #keyId}; optional {@link #aad}.</li>
 *   <li>{@code Health}: nothing else.</li>
 * </ul>
 *
 * <p><b>Control plane</b> (uses the admin token):
 * <ul>
 *   <li>{@code CreateKeyGroup} / {@code RotateKeyGroup}: {@link #keyId}.</li>
 *   <li>{@code ListKeyGroups}: nothing else.</li>
 *   <li>{@code DisableVersion} / {@code EnableVersion} / {@code DestroyVersion}:
 *       {@link #keyId} + {@link #version}.</li>
 * </ul>
 *
 * <p>{@link #token} is required on every request and is never logged. {@link #keyId}
 * names a key group (omit for the {@code "default"} group on data-plane ops).
 *
 * @param type       the operation.
 * @param token      the shared API or admin token.
 * @param keyId      the key group name (data: target group; control: subject group).
 * @param version    the KEK version (control-plane version ops).
 * @param plaintext  base64 plaintext (Encrypt).
 * @param ciphertext base64 ciphertext or wrapped DEK (Decrypt / ReEncrypt source).
 * @param aad        base64 encryption context (optional, crypto ops).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record KmsRequest(
    RequestType type,
    String token,
    String keyId,
    Long version,
    String plaintext,
    String ciphertext,
    String aad) {

  /** @return a Health request. */
  public static KmsRequest health(final String token) {
    return new KmsRequest(RequestType.HEALTH, token, null, null, null, null, null);
  }

  /** @return a GenerateDataKey request for a group (null keyId → default). */
  public static KmsRequest generateDataKey(final String token, final String keyId, final String aadBase64) {
    return new KmsRequest(RequestType.GENERATE_DATA_KEY, token, keyId, null, null, null, aadBase64);
  }

  /** @return an Encrypt request for a group (null keyId → default). */
  public static KmsRequest encrypt(final String token, final String keyId,
                                   final String plaintextBase64, final String aadBase64) {
    return new KmsRequest(RequestType.ENCRYPT, token, keyId, null, plaintextBase64, null, aadBase64);
  }

  /** @return a Decrypt request. */
  public static KmsRequest decrypt(final String token, final String ciphertextBase64, final String aadBase64) {
    return new KmsRequest(RequestType.DECRYPT, token, null, null, null, ciphertextBase64, aadBase64);
  }

  /** @return a ReEncrypt request moving a blob to {@code destKeyId}'s active version. */
  public static KmsRequest reEncrypt(final String token, final String destKeyId,
                                     final String ciphertextBase64, final String aadBase64) {
    return new KmsRequest(RequestType.RE_ENCRYPT, token, destKeyId, null, null, ciphertextBase64, aadBase64);
  }

  /** @return a CreateKeyGroup request. */
  public static KmsRequest createKeyGroup(final String token, final String keyId) {
    return new KmsRequest(RequestType.CREATE_KEY_GROUP, token, keyId, null, null, null, null);
  }

  /** @return a RotateKeyGroup request. */
  public static KmsRequest rotateKeyGroup(final String token, final String keyId) {
    return new KmsRequest(RequestType.ROTATE_KEY_GROUP, token, keyId, null, null, null, null);
  }

  /** @return a ListKeyGroups request. */
  public static KmsRequest listKeyGroups(final String token) {
    return new KmsRequest(RequestType.LIST_KEY_GROUPS, token, null, null, null, null, null);
  }

  /** @return a version lifecycle request ({@code Disable}/{@code Enable}/{@code Destroy}). */
  public static KmsRequest versionOp(final RequestType type, final String token,
                                     final String keyId, final long version) {
    return new KmsRequest(type, token, keyId, version, null, null, null);
  }
}
