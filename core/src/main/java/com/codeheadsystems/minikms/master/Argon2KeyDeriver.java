package com.codeheadsystems.minikms.master;

import com.codeheadsystems.minikms.crypto.AesGcm;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Derives a 256-bit master key from a passphrase using Argon2id (Bouncy Castle).
 *
 * <p>Argon2id is a memory-hard password hashing function: deriving the key costs
 * a tunable amount of memory and time ({@link Argon2Settings}), which is what
 * makes a stolen keystore file expensive to brute-force. The per-install random
 * salt ensures two installs with the same passphrase still get different keys
 * and defeats precomputation.
 *
 * <p>The passphrase is handled as a {@code char[]} and converted to UTF-8 bytes
 * only transiently; both the transient bytes are zeroed before returning. The
 * caller still owns (and should zero) the original {@code char[]}.
 */
public final class Argon2KeyDeriver {

  private Argon2KeyDeriver() {
  }

  /**
   * Derive a 32-byte master key.
   *
   * @param passphrase the secret passphrase (not mutated; caller should zero it afterwards).
   * @param salt       the per-install random salt.
   * @param settings   the Argon2 cost parameters.
   * @return a freshly allocated 32-byte key; the caller owns it and should zero it on shutdown.
   */
  public static byte[] deriveMasterKey(final char[] passphrase, final byte[] salt, final Argon2Settings settings) {
    if (passphrase == null || passphrase.length == 0) {
      throw new IllegalArgumentException("passphrase must not be empty");
    }
    if (salt == null || salt.length == 0) {
      throw new IllegalArgumentException("salt must not be empty");
    }
    final byte[] passphraseBytes = toUtf8(passphrase);
    try {
      final Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
          .withVersion(Argon2Parameters.ARGON2_VERSION_13)
          .withIterations(settings.iterations())
          .withMemoryAsKB(settings.memoryKiB())
          .withParallelism(settings.parallelism())
          .withSalt(salt)
          .build();
      final Argon2BytesGenerator generator = new Argon2BytesGenerator();
      generator.init(params);
      final byte[] key = new byte[AesGcm.KEY_LENGTH_BYTES];
      generator.generateBytes(passphraseBytes, key);
      return key;
    } finally {
      Arrays.fill(passphraseBytes, (byte) 0);
    }
  }

  private static byte[] toUtf8(final char[] chars) {
    final java.nio.CharBuffer charBuffer = java.nio.CharBuffer.wrap(chars);
    final java.nio.ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
    final byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
    // Zero Jackson/JDK's intermediate buffer.
    Arrays.fill(byteBuffer.array(), (byte) 0);
    return bytes;
  }
}
