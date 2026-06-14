package com.codeheadsystems.minikms.client;

import java.nio.file.Path;

/**
 * Shared connection helper for the CLIs: pick the TCP or Unix transport from the
 * usual {@code --tcp}/{@code --unix} options and open a {@link KmsClient}.
 */
final class Connections {

  private static final String DEFAULT_TCP = "127.0.0.1:9123";

  private Connections() {
  }

  /**
   * @param tcp   {@code HOST:PORT} (used when {@code unix} is null; null → default loopback).
   * @param unix  Unix socket path (takes precedence when set).
   * @param token the token to carry on every request.
   * @return a connected client.
   */
  static KmsClient connect(final String tcp, final String unix, final String token) {
    if (unix != null) {
      return KmsClient.connectUnix(Path.of(unix), token);
    }
    final String target = tcp != null ? tcp : DEFAULT_TCP;
    final int colon = target.lastIndexOf(':');
    if (colon < 0) {
      throw new KmsClientException(null, "--tcp must be HOST:PORT");
    }
    final int port;
    try {
      port = Integer.parseInt(target.substring(colon + 1));
    } catch (final NumberFormatException e) {
      throw new KmsClientException(null, "invalid port in --tcp value: " + target);
    }
    return KmsClient.connectTcp(target.substring(0, colon), port, token);
  }
}
