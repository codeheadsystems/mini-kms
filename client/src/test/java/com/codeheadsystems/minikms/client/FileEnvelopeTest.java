package com.codeheadsystems.minikms.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class FileEnvelopeTest {

  @Test
  void serializeThenParseRoundTrips() {
    final FileEnvelope original = new FileEnvelope(new byte[]{1, 2, 3}, new byte[]{9, 8, 7, 6});
    final FileEnvelope parsed = FileEnvelope.parse(original.serialize());
    assertArrayEquals(new byte[]{1, 2, 3}, parsed.wrappedDek());
    assertArrayEquals(new byte[]{9, 8, 7, 6}, parsed.ciphertext());
  }

  @Test
  void rejectsBadMagic() {
    final byte[] bytes = new byte[20];
    bytes[0] = 'X';
    assertThrows(IllegalArgumentException.class, () -> FileEnvelope.parse(bytes));
  }

  @Test
  void rejectsTooShort() {
    assertThrows(IllegalArgumentException.class, () -> FileEnvelope.parse(new byte[]{'M', 'K'}));
  }

  @Test
  void rejectsCorruptLength() {
    // Valid magic, but a wrapped-key length far larger than the remaining bytes.
    final byte[] bytes = {'M', 'K', 'E', '1', 0x7F, 0x00, 0x00, 0x00, 1, 2};
    assertThrows(IllegalArgumentException.class, () -> FileEnvelope.parse(bytes));
  }
}
