package com.codeheadsystems.minikms.client;

import com.codeheadsystems.minikms.protocol.ErrorCode;

/**
 * Thrown by {@link KmsClient} when the server returns an error response or the
 * connection fails. Carries the server's {@link ErrorCode} when available.
 */
public class KmsClientException extends RuntimeException {

  private final ErrorCode errorCode;

  /**
   * @param errorCode the server error code, or {@code null} for transport failures.
   * @param message   a human-readable description.
   */
  public KmsClientException(final ErrorCode errorCode, final String message) {
    super(message);
    this.errorCode = errorCode;
  }

  /**
   * @param message a description of a client-side/transport failure.
   * @param cause   the underlying cause.
   */
  public KmsClientException(final String message, final Throwable cause) {
    super(message, cause);
    this.errorCode = null;
  }

  /** @return the server error code, or {@code null} if this was a transport failure. */
  public ErrorCode errorCode() {
    return errorCode;
  }
}
