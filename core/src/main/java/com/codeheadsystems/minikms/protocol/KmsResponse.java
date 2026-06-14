package com.codeheadsystems.minikms.protocol;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/**
 * A single response object, one per line of newline-delimited JSON.
 *
 * <p>{@link #status} is {@code "ok"} or {@code "error"}. On error, {@link #errorCode}
 * and {@link #message} are set. On success the fields relevant to the request are
 * set (binary as base64):
 *
 * <ul>
 *   <li>{@code GenerateDataKey}: {@link #plaintextDataKey} + {@link #wrappedDataKey}.</li>
 *   <li>{@code Encrypt} / {@code ReEncrypt}: {@link #ciphertext}.</li>
 *   <li>{@code Decrypt}: {@link #plaintext}.</li>
 *   <li>{@code Health}: {@link #detail}.</li>
 *   <li>{@code CreateKeyGroup} / {@code RotateKeyGroup}: {@link #keyGroup}.</li>
 *   <li>{@code ListKeyGroups}: {@link #keyGroups}.</li>
 *   <li>{@code Disable/Enable/DestroyVersion}: {@link #detail}.</li>
 * </ul>
 *
 * @param status           "ok" or "error".
 * @param errorCode        stable error code (error only).
 * @param message          human-readable, non-sensitive message (error only).
 * @param plaintextDataKey base64 plaintext DEK (GenerateDataKey).
 * @param wrappedDataKey   base64 wrapped DEK (GenerateDataKey).
 * @param ciphertext       base64 ciphertext (Encrypt / ReEncrypt).
 * @param plaintext        base64 plaintext (Decrypt).
 * @param detail           free-form detail (Health, version ops).
 * @param keyGroup         a single key group (Create/Rotate).
 * @param keyGroups        all key groups (ListKeyGroups).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record KmsResponse(
    Status status,
    ErrorCode errorCode,
    String message,
    String plaintextDataKey,
    String wrappedDataKey,
    String ciphertext,
    String plaintext,
    String detail,
    KeyGroupView keyGroup,
    List<KeyGroupView> keyGroups) {

  /** The response status discriminator. */
  public enum Status {
    /** Operation succeeded. */
    OK,
    /** Operation failed; see {@link KmsResponse#errorCode()}. */
    ERROR;

    /** @return lowercase wire value. */
    @com.fasterxml.jackson.annotation.JsonValue
    public String wireValue() {
      return name().toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * @param value wire string.
     * @return matching status.
     */
    @com.fasterxml.jackson.annotation.JsonCreator
    public static Status fromWire(final String value) {
      return valueOf(value.toUpperCase(java.util.Locale.ROOT));
    }
  }

  /** @return whether this response indicates success. */
  public boolean isOk() {
    return status == Status.OK;
  }

  /** @return an error response. */
  public static KmsResponse error(final ErrorCode code, final String message) {
    return new KmsResponse(Status.ERROR, code, message, null, null, null, null, null, null, null);
  }

  /** @return a GenerateDataKey success response. */
  public static KmsResponse dataKey(final String plaintextDataKeyBase64, final String wrappedDataKeyBase64) {
    return new KmsResponse(Status.OK, null, null, plaintextDataKeyBase64, wrappedDataKeyBase64,
        null, null, null, null, null);
  }

  /** @return an Encrypt/ReEncrypt success response. */
  public static KmsResponse encrypted(final String ciphertextBase64) {
    return new KmsResponse(Status.OK, null, null, null, null, ciphertextBase64, null, null, null, null);
  }

  /** @return a Decrypt success response. */
  public static KmsResponse decrypted(final String plaintextBase64) {
    return new KmsResponse(Status.OK, null, null, null, null, null, plaintextBase64, null, null, null);
  }

  /** @return a Health success response. */
  public static KmsResponse healthy() {
    return new KmsResponse(Status.OK, null, null, null, null, null, null, "ok", null, null);
  }

  /** @return a plain ok response carrying a detail message (e.g. version ops). */
  public static KmsResponse ok(final String detail) {
    return new KmsResponse(Status.OK, null, null, null, null, null, null, detail, null, null);
  }

  /** @return a single-key-group success response (Create/Rotate). */
  public static KmsResponse group(final KeyGroupView group) {
    return new KmsResponse(Status.OK, null, null, null, null, null, null, null, group, null);
  }

  /** @return a key-group list success response. */
  public static KmsResponse groups(final List<KeyGroupView> groups) {
    return new KmsResponse(Status.OK, null, null, null, null, null, null, null, null, groups);
  }
}
