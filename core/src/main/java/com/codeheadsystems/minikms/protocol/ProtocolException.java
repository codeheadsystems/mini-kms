package com.codeheadsystems.minikms.protocol;

/**
 * Thrown when a protocol line cannot be parsed or serialized.
 *
 * <p>Maps to {@link ErrorCode#INVALID_REQUEST} on the server side.
 */
public class ProtocolException extends RuntimeException {

  /**
   * @param message a non-sensitive description of the framing/parse failure.
   */
  public ProtocolException(final String message) {
    super(message);
  }
}
