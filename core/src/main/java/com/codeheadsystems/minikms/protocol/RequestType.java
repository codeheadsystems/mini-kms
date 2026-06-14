package com.codeheadsystems.minikms.protocol;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The request operations the server understands, each tagged with the
 * {@link RequestPlane} that determines which token authorizes it.
 *
 * <p>The JSON wire value is the PascalCase name; {@code "Ping"} aliases
 * {@link #HEALTH}.
 */
public enum RequestType {

  // ---- DATA PLANE (API token) ----
  /** Mint a new data key; returns plaintext + wrapped DEK. */
  GENERATE_DATA_KEY("GenerateDataKey", RequestPlane.DATA),
  /** Encrypt a small blob under a key group's active version. */
  ENCRYPT("Encrypt", RequestPlane.DATA),
  /** Decrypt a blob or unwrap a data key. */
  DECRYPT("Decrypt", RequestPlane.DATA),
  /** Re-encrypt a blob to a destination group's active version. */
  RE_ENCRYPT("ReEncrypt", RequestPlane.DATA),
  /** Liveness check; requires no crypto. */
  HEALTH("Health", RequestPlane.DATA),

  // ---- CONTROL PLANE (admin token) ----
  /** Create a new key group. */
  CREATE_KEY_GROUP("CreateKeyGroup", RequestPlane.CONTROL),
  /** Rotate a key group (new active version). */
  ROTATE_KEY_GROUP("RotateKeyGroup", RequestPlane.CONTROL),
  /** List all key groups and their versions. */
  LIST_KEY_GROUPS("ListKeyGroups", RequestPlane.CONTROL),
  /** Disable a non-active version. */
  DISABLE_VERSION("DisableVersion", RequestPlane.CONTROL),
  /** Re-enable a disabled version. */
  ENABLE_VERSION("EnableVersion", RequestPlane.CONTROL),
  /** Destroy a non-active version's key material (irreversible). */
  DESTROY_VERSION("DestroyVersion", RequestPlane.CONTROL);

  private final String wireValue;
  private final RequestPlane plane;

  RequestType(final String wireValue, final RequestPlane plane) {
    this.wireValue = wireValue;
    this.plane = plane;
  }

  /** @return the JSON wire representation. */
  @JsonValue
  public String wireValue() {
    return wireValue;
  }

  /** @return the plane this operation belongs to. */
  public RequestPlane plane() {
    return plane;
  }

  /**
   * Parse a wire value tolerantly.
   *
   * @param value the JSON string (case-insensitive; {@code "Ping"} → {@link #HEALTH}).
   * @return the matching request type.
   * @throws IllegalArgumentException if unrecognized.
   */
  @JsonCreator
  public static RequestType fromWire(final String value) {
    if (value == null) {
      throw new IllegalArgumentException("request type is required");
    }
    if (value.equalsIgnoreCase("Ping")) {
      return HEALTH;
    }
    for (final RequestType type : values()) {
      if (type.wireValue.equalsIgnoreCase(value)) {
        return type;
      }
    }
    throw new IllegalArgumentException("unknown request type: " + value);
  }
}
