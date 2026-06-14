package com.codeheadsystems.minikms.crypto;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Self-describing on-the-wire format for a single AES-256-GCM ciphertext.
 *
 * <p>Every encrypted blob produced by mini-kms starts with a small header so the
 * format can evolve without ambiguity:
 *
 * <pre>
 *   +---------+---------+------------------+-------------------------------+
 *   | version | alg id  | nonce (12 bytes) | ciphertext + GCM tag (16 B)   |
 *   |  1 byte | 1 byte  |                  | (variable length)             |
 *   +---------+---------+------------------+-------------------------------+
 * </pre>
 *
 * <p>The nonce length is fixed by the algorithm id (AES-256-GCM uses a 96-bit /
 * 12-byte nonce, the value NIST recommends for GCM). The GCM authentication tag
 * is appended to the ciphertext by the JCA, so it is carried inside the
 * {@code ciphertext} field here. AAD ("encryption context") is authenticated but
 * never stored in the envelope; the caller must supply the same AAD to decrypt.
 *
 * <p>This is a pure data/format type: it performs no encryption itself.
 */
public record EnvelopeFormat(byte version, byte algorithmId, byte[] nonce, byte[] ciphertext) {

  /** Current format version. */
  public static final byte VERSION_1 = 0x01;

  /** Algorithm id for AES-256-GCM with a 96-bit nonce and 128-bit tag. */
  public static final byte ALG_AES_256_GCM = 0x01;

  /** GCM nonce length in bytes (96 bits). */
  public static final int NONCE_LENGTH = 12;

  /** GCM authentication tag length in bits. */
  public static final int TAG_LENGTH_BITS = 128;

  private static final int HEADER_LENGTH = 2 + NONCE_LENGTH;

  /** Compact constructor validating the structural invariants of the format. */
  public EnvelopeFormat {
    if (nonce == null || nonce.length != NONCE_LENGTH) {
      throw new IllegalArgumentException("nonce must be exactly " + NONCE_LENGTH + " bytes");
    }
    if (ciphertext == null) {
      throw new IllegalArgumentException("ciphertext must not be null");
    }
    // Defensive copies so the record is genuinely immutable.
    nonce = nonce.clone();
    ciphertext = ciphertext.clone();
  }

  /** Serialize this envelope to a single byte array (header + nonce + ciphertext). */
  public byte[] serialize() {
    return ByteBuffer.allocate(HEADER_LENGTH + ciphertext.length)
        .put(version)
        .put(algorithmId)
        .put(nonce)
        .put(ciphertext)
        .array();
  }

  /**
   * Parse a serialized envelope.
   *
   * @param bytes the serialized form produced by {@link #serialize()}.
   * @return the parsed envelope.
   * @throws IllegalArgumentException if the bytes are too short or the header is unrecognized.
   */
  public static EnvelopeFormat parse(final byte[] bytes) {
    if (bytes == null || bytes.length < HEADER_LENGTH) {
      throw new IllegalArgumentException("ciphertext blob is too short to be a valid envelope");
    }
    final byte version = bytes[0];
    if (version != VERSION_1) {
      throw new IllegalArgumentException("unsupported envelope version: " + version);
    }
    final byte algorithmId = bytes[1];
    if (algorithmId != ALG_AES_256_GCM) {
      throw new IllegalArgumentException("unsupported algorithm id: " + algorithmId);
    }
    final byte[] nonce = Arrays.copyOfRange(bytes, 2, 2 + NONCE_LENGTH);
    final byte[] ciphertext = Arrays.copyOfRange(bytes, HEADER_LENGTH, bytes.length);
    return new EnvelopeFormat(version, algorithmId, nonce, ciphertext);
  }

  @Override
  public byte[] nonce() {
    return nonce.clone();
  }

  @Override
  public byte[] ciphertext() {
    return ciphertext.clone();
  }
}
