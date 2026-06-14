package com.codeheadsystems.minikms.keyring;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The client-facing ciphertext format: a {@link KekId} header followed by the
 * raw AES-GCM envelope produced under that KEK version.
 *
 * <p>This is the layer that makes rotation work. Internally the bytes are simply
 * "which key wrapped me" + "the authenticated ciphertext":
 *
 * <pre>
 *   +---------+-------------+----------------+-----------+---------------------------+
 *   | version | groupIdLen  | groupId        | kekVer    | inner AES-GCM envelope    |
 *   | 1 byte  | 1 byte (N)  | N bytes (UTF-8)| 8 bytes BE| (crypto.EnvelopeFormat)   |
 *   +---------+-------------+----------------+-----------+---------------------------+
 *    0x02
 * </pre>
 *
 * <p>The inner envelope is a {@code com.codeheadsystems.minikms.crypto.EnvelopeFormat}
 * (its own version + algorithm id + nonce + ciphertext + tag). Decryption reads
 * the {@link KekId}, looks up that exact KEK version in the keyring, and decrypts
 * the inner envelope with it.
 *
 * <p>By contrast, KEK <em>versions themselves</em> and the verification token are
 * stored wrapped under the single root key and use the bare inner envelope with
 * no {@code KekId} header (there is only one root key, so none is needed).
 */
public record KekEnvelope(KekId kekId, byte[] innerEnvelope) {

  /** Current client-facing envelope version. */
  public static final byte VERSION_2 = 0x02;

  /** Defensive copy. */
  public KekEnvelope {
    if (kekId == null) {
      throw new IllegalArgumentException("kekId is required");
    }
    if (innerEnvelope == null || innerEnvelope.length == 0) {
      throw new IllegalArgumentException("innerEnvelope must not be empty");
    }
    innerEnvelope = innerEnvelope.clone();
  }

  /** Serialize to the client-facing blob. */
  public byte[] serialize() {
    final byte[] groupId = kekId.keyGroupId().getBytes(StandardCharsets.UTF_8);
    return ByteBuffer.allocate(1 + 1 + groupId.length + 8 + innerEnvelope.length)
        .put(VERSION_2)
        .put((byte) groupId.length)
        .put(groupId)
        .putLong(kekId.version())
        .put(innerEnvelope)
        .array();
  }

  /**
   * Parse a client-facing blob.
   *
   * @param bytes the serialized form from {@link #serialize()}.
   * @return the parsed envelope.
   * @throws IllegalArgumentException if the header is malformed or the version is unknown.
   */
  public static KekEnvelope parse(final byte[] bytes) {
    if (bytes == null || bytes.length < 3) {
      throw new IllegalArgumentException("ciphertext blob is too short");
    }
    if (bytes[0] != VERSION_2) {
      throw new IllegalArgumentException("unsupported ciphertext version: " + bytes[0]);
    }
    final int groupIdLen = bytes[1] & 0xFF;
    final int headerEnd = 2 + groupIdLen + 8;
    if (groupIdLen == 0 || bytes.length <= headerEnd) {
      throw new IllegalArgumentException("malformed ciphertext header");
    }
    final ByteBuffer buffer = ByteBuffer.wrap(bytes, 2, bytes.length - 2);
    final byte[] groupId = new byte[groupIdLen];
    buffer.get(groupId);
    final long version = buffer.getLong();
    final byte[] inner = new byte[buffer.remaining()];
    buffer.get(inner);
    return new KekEnvelope(new KekId(new String(groupId, StandardCharsets.UTF_8), version), inner);
  }

  /**
   * Read only the {@link KekId} from a blob without copying the ciphertext.
   * Used by the request handler to authorize access before decrypting.
   *
   * @param bytes the serialized client-facing blob.
   * @return the key id the blob was wrapped under.
   */
  public static KekId peekKekId(final byte[] bytes) {
    return parse(bytes).kekId();
  }

  @Override
  public byte[] innerEnvelope() {
    return innerEnvelope.clone();
  }
}
