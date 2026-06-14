package com.codeheadsystems.minikms.server;

import java.io.IOException;

/** Raised when an incoming request line exceeds the configured frame limit. */
final class FrameTooLargeException extends IOException {

  FrameTooLargeException(final int limit) {
    super("request frame exceeded limit of " + limit + " bytes");
  }
}
