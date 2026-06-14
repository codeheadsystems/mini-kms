package com.codeheadsystems.minikms.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class EnvelopeFormatTest {

  @Test
  void serializeThenParseRoundTrips() {
    final byte[] nonce = new byte[EnvelopeFormat.NONCE_LENGTH];
    Arrays.fill(nonce, (byte) 7);
    final byte[] ciphertext = {1, 2, 3, 4, 5};
    final EnvelopeFormat original =
        new EnvelopeFormat(EnvelopeFormat.VERSION_1, EnvelopeFormat.ALG_AES_256_GCM, nonce, ciphertext);

    final EnvelopeFormat parsed = EnvelopeFormat.parse(original.serialize());

    assertEquals(EnvelopeFormat.VERSION_1, parsed.version());
    assertEquals(EnvelopeFormat.ALG_AES_256_GCM, parsed.algorithmId());
    assertArrayEquals(nonce, parsed.nonce());
    assertArrayEquals(ciphertext, parsed.ciphertext());
  }

  @Test
  void serializedLayoutHasHeaderThenNonceThenCiphertext() {
    final byte[] nonce = new byte[EnvelopeFormat.NONCE_LENGTH];
    final byte[] ciphertext = {(byte) 0xAB};
    final byte[] bytes =
        new EnvelopeFormat(EnvelopeFormat.VERSION_1, EnvelopeFormat.ALG_AES_256_GCM, nonce, ciphertext)
            .serialize();

    assertEquals(2 + EnvelopeFormat.NONCE_LENGTH + 1, bytes.length);
    assertEquals(EnvelopeFormat.VERSION_1, bytes[0]);
    assertEquals(EnvelopeFormat.ALG_AES_256_GCM, bytes[1]);
    assertEquals((byte) 0xAB, bytes[bytes.length - 1]);
  }

  @Test
  void rejectsWrongNonceLength() {
    assertThrows(IllegalArgumentException.class, () ->
        new EnvelopeFormat(EnvelopeFormat.VERSION_1, EnvelopeFormat.ALG_AES_256_GCM, new byte[5], new byte[1]));
  }

  @Test
  void rejectsUnknownVersion() {
    final byte[] bytes = new byte[2 + EnvelopeFormat.NONCE_LENGTH + 1];
    bytes[0] = 0x09; // bogus version
    bytes[1] = EnvelopeFormat.ALG_AES_256_GCM;
    assertThrows(IllegalArgumentException.class, () -> EnvelopeFormat.parse(bytes));
  }

  @Test
  void rejectsTooShortBlob() {
    assertThrows(IllegalArgumentException.class, () -> EnvelopeFormat.parse(new byte[3]));
  }
}
