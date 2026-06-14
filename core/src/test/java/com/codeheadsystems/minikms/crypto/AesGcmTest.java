package com.codeheadsystems.minikms.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

class AesGcmTest {

  private final AesGcm aesGcm = new AesGcm();
  private final SecretKey key = AesGcm.toKey(filledKey());

  @Test
  void roundTripsWithoutAad() {
    final byte[] plaintext = "hello envelope encryption".getBytes(StandardCharsets.UTF_8);
    final byte[] ciphertext = aesGcm.encrypt(key, plaintext, null);
    assertArrayEquals(plaintext, aesGcm.decrypt(key, ciphertext, null));
  }

  @Test
  void roundTripsWithAad() {
    final byte[] plaintext = {1, 2, 3};
    final byte[] aad = "context".getBytes(StandardCharsets.UTF_8);
    final byte[] ciphertext = aesGcm.encrypt(key, plaintext, aad);
    assertArrayEquals(plaintext, aesGcm.decrypt(key, ciphertext, aad));
  }

  @Test
  void freshNonceMakesCiphertextsDiffer() {
    final byte[] plaintext = {9, 9, 9};
    final byte[] a = aesGcm.encrypt(key, plaintext, null);
    final byte[] b = aesGcm.encrypt(key, plaintext, null);
    assertFalse(Arrays.equals(a, b), "each encryption must use a fresh nonce");
  }

  @Test
  void tamperedCiphertextFailsAuthentication() {
    final byte[] ciphertext = aesGcm.encrypt(key, new byte[]{4, 5, 6}, null);
    ciphertext[ciphertext.length - 1] ^= 0x01; // flip a bit in the tag
    assertThrows(AeadException.class, () -> aesGcm.decrypt(key, ciphertext, null));
  }

  @Test
  void wrongAadFailsAuthentication() {
    final byte[] ciphertext = aesGcm.encrypt(key, new byte[]{7}, "right".getBytes(StandardCharsets.UTF_8));
    assertThrows(AeadException.class, () ->
        aesGcm.decrypt(key, ciphertext, "wrong".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void wrongKeyFailsAuthentication() {
    final byte[] ciphertext = aesGcm.encrypt(key, new byte[]{1}, null);
    final SecretKey otherKey = AesGcm.toKey(new byte[AesGcm.KEY_LENGTH_BYTES]);
    assertThrows(AeadException.class, () -> aesGcm.decrypt(otherKey, ciphertext, null));
  }

  private static byte[] filledKey() {
    final byte[] key = new byte[AesGcm.KEY_LENGTH_BYTES];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }
    return key;
  }
}
