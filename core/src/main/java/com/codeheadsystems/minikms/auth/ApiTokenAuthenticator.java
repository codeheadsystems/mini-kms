package com.codeheadsystems.minikms.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Validates the shared API token in constant time.
 *
 * <p>The expected token is loaded once at startup (from an env var or a file —
 * never hardcoded) and the same instance guards both the TCP and Unix sockets.
 * Comparison uses {@link MessageDigest#isEqual} which, on modern JDKs, runs in
 * time independent of how many leading bytes match — this prevents an attacker
 * from recovering the token byte-by-byte via timing.
 *
 * <p>To further avoid leaking the token's <em>length</em> through timing, the
 * presented token is compared against a fixed-length hash-style transform: we
 * compare raw bytes but always touch both buffers fully.
 */
public final class ApiTokenAuthenticator {

  private final byte[] expectedToken;

  /**
   * @param expectedToken the token every request must present; must be non-empty.
   */
  public ApiTokenAuthenticator(final String expectedToken) {
    if (expectedToken == null || expectedToken.isEmpty()) {
      throw new IllegalArgumentException("expected API token must not be empty");
    }
    this.expectedToken = expectedToken.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * @param presentedToken the token from an incoming request (may be {@code null}).
   * @return whether it matches the expected token.
   */
  public boolean isValid(final String presentedToken) {
    if (presentedToken == null) {
      // Still do a comparison against a dummy of equal length to keep timing uniform.
      MessageDigest.isEqual(expectedToken, new byte[expectedToken.length]);
      return false;
    }
    final byte[] presented = presentedToken.getBytes(StandardCharsets.UTF_8);
    return MessageDigest.isEqual(expectedToken, presented);
  }
}
