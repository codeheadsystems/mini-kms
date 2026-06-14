package com.codeheadsystems.minikms.protocol;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Stable, machine-readable error codes carried on error responses.
 *
 * <p>Codes are intentionally coarse and never reveal cryptographic detail. In
 * particular {@link #DECRYPTION_FAILED} is returned for any AEAD failure (wrong
 * key, wrong AAD, or tampering) so the protocol cannot be used as an oracle.
 */
public enum ErrorCode {

  /** Missing or incorrect API/admin token. */
  AUTH_FAILED("AuthFailed"),
  /** Authenticated, but not permitted to use this key group (authorization policy). */
  UNAUTHORIZED("Unauthorized"),
  /** Malformed JSON, unknown type, missing/invalid fields, or invalid key-management request. */
  INVALID_REQUEST("InvalidRequest"),
  /** AEAD authentication failed on decrypt/unwrap. */
  DECRYPTION_FAILED("DecryptionFailed"),
  /** Request frame exceeded the configured size limit. */
  FRAME_TOO_LARGE("FrameTooLarge"),
  /** Unexpected server-side failure. */
  INTERNAL_ERROR("InternalError");

  private final String wireValue;

  ErrorCode(final String wireValue) {
    this.wireValue = wireValue;
  }

  /** @return the JSON wire representation. */
  @JsonValue
  public String wireValue() {
    return wireValue;
  }

  /**
   * @param value the JSON string.
   * @return the matching code.
   */
  @JsonCreator
  public static ErrorCode fromWire(final String value) {
    for (final ErrorCode code : values()) {
      if (code.wireValue.equalsIgnoreCase(value)) {
        return code;
      }
    }
    throw new IllegalArgumentException("unknown error code: " + value);
  }
}
