package com.codeheadsystems.minikms.client;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * On-disk container for an envelope-encrypted file: the wrapped DEK stored next
 * to the ciphertext it protects.
 *
 * <p>This is the artifact the CLI writes. It demonstrates the core idea of
 * envelope encryption: the bulk data is encrypted locally with a data key, and
 * only the <em>wrapped</em> data key travels with it — the KMS is needed (and the
 * master key only exists) to unwrap it again.
 *
 * <pre>
 *   +--------+------------------+-------------------+----------------------+
 *   | magic  | wrapped DEK len  | wrapped DEK       | file ciphertext      |
 *   | "MKE1" | 4 bytes (int BE) | (len bytes)       | (remaining bytes)    |
 *   +--------+------------------+-------------------+----------------------+
 * </pre>
 *
 * <p>The file ciphertext is itself a {@code core} {@code EnvelopeFormat} blob
 * (version + alg + nonce + AES-GCM ciphertext) produced with the plaintext DEK.
 */
public record FileEnvelope(byte[] wrappedDek, byte[] ciphertext) {

  private static final byte[] MAGIC = {'M', 'K', 'E', '1'};

  /** Defensive copies. */
  public FileEnvelope {
    wrappedDek = wrappedDek.clone();
    ciphertext = ciphertext.clone();
  }

  /** Serialize to the on-disk container bytes. */
  public byte[] serialize() {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(MAGIC);
    out.writeBytes(ByteBuffer.allocate(4).putInt(wrappedDek.length).array());
    out.writeBytes(wrappedDek);
    out.writeBytes(ciphertext);
    return out.toByteArray();
  }

  /**
   * Parse a container produced by {@link #serialize()}.
   *
   * @param bytes the file bytes.
   * @return the parsed envelope.
   * @throws IllegalArgumentException if the magic or length is invalid.
   */
  public static FileEnvelope parse(final byte[] bytes) {
    if (bytes == null || bytes.length < MAGIC.length + 4) {
      throw new IllegalArgumentException("file is too short to be a mini-kms envelope");
    }
    if (!Arrays.equals(Arrays.copyOfRange(bytes, 0, MAGIC.length), MAGIC)) {
      throw new IllegalArgumentException("not a mini-kms envelope file (bad magic)");
    }
    final ByteBuffer buffer = ByteBuffer.wrap(bytes, MAGIC.length, bytes.length - MAGIC.length);
    final int wrappedLen = buffer.getInt();
    if (wrappedLen < 0 || wrappedLen > buffer.remaining()) {
      throw new IllegalArgumentException("corrupt mini-kms envelope (bad wrapped-key length)");
    }
    final byte[] wrapped = new byte[wrappedLen];
    buffer.get(wrapped);
    final byte[] ciphertext = new byte[buffer.remaining()];
    buffer.get(ciphertext);
    return new FileEnvelope(wrapped, ciphertext);
  }

  @Override
  public byte[] wrappedDek() {
    return wrappedDek.clone();
  }

  @Override
  public byte[] ciphertext() {
    return ciphertext.clone();
  }
}
