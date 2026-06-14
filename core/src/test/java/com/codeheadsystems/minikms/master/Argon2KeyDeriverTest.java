package com.codeheadsystems.minikms.master;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.codeheadsystems.minikms.crypto.AesGcm;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class Argon2KeyDeriverTest {

  // Small parameters keep the test fast; production uses Argon2Settings.defaults().
  private static final Argon2Settings FAST = new Argon2Settings(1024, 1, 1);

  @Test
  void derivesA256BitKey() {
    final byte[] key = Argon2KeyDeriver.deriveMasterKey("pw".toCharArray(), salt(0x11), FAST);
    assertEquals(AesGcm.KEY_LENGTH_BYTES, key.length);
  }

  @Test
  void sameInputsReproduceSameKey() {
    final byte[] a = Argon2KeyDeriver.deriveMasterKey("correct horse".toCharArray(), salt(0x22), FAST);
    final byte[] b = Argon2KeyDeriver.deriveMasterKey("correct horse".toCharArray(), salt(0x22), FAST);
    assertArrayEquals(a, b, "same passphrase + salt + params must reproduce the key across restarts");
  }

  @Test
  void differentSaltProducesDifferentKey() {
    final byte[] a = Argon2KeyDeriver.deriveMasterKey("pw".toCharArray(), salt(0x01), FAST);
    final byte[] b = Argon2KeyDeriver.deriveMasterKey("pw".toCharArray(), salt(0x02), FAST);
    assertFalse(Arrays.equals(a, b), "the per-install salt must change the derived key");
  }

  @Test
  void differentPassphraseProducesDifferentKey() {
    final byte[] a = Argon2KeyDeriver.deriveMasterKey("alpha".toCharArray(), salt(0x33), FAST);
    final byte[] b = Argon2KeyDeriver.deriveMasterKey("bravo".toCharArray(), salt(0x33), FAST);
    assertFalse(Arrays.equals(a, b));
  }

  private static byte[] salt(final int fill) {
    final byte[] salt = new byte[16];
    Arrays.fill(salt, (byte) fill);
    return salt;
  }
}
