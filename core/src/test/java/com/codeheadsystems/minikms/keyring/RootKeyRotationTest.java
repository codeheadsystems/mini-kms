package com.codeheadsystems.minikms.keyring;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.codeheadsystems.minikms.master.Argon2Settings;
import com.codeheadsystems.minikms.master.WrongPassphraseException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RootKeyRotationTest {

  private static final Argon2Settings FAST = new Argon2Settings(2048, 1, 1);

  @TempDir
  Path tempDir;

  @Test
  void changingPassphrasePreservesAllCiphertexts() {
    final Path keystore = tempDir.resolve("keystore.json");
    final byte[] underV1;
    final byte[] underV2;
    try (LocalKeyring keyring = LocalKeyring.bootstrap(keystore, "old-pass".toCharArray(), FAST)) {
      underV1 = keyring.encrypt("default", new byte[]{1, 1, 1}, null);
      keyring.rotateKeyGroup("default");
      underV2 = keyring.encrypt("default", new byte[]{2, 2, 2}, null);
    }

    // Offline root rotation under a new passphrase.
    RootKeyRotation.changePassphrase(keystore, "old-pass".toCharArray(), "new-pass".toCharArray(), FAST);

    // Old passphrase no longer opens it; new one does, and all ciphertexts still decrypt.
    assertThrows(WrongPassphraseException.class, () ->
        LocalKeyring.bootstrap(keystore, "old-pass".toCharArray(), FAST));
    try (LocalKeyring reopened = LocalKeyring.bootstrap(keystore, "new-pass".toCharArray(), FAST)) {
      assertArrayEquals(new byte[]{1, 1, 1}, reopened.decrypt(underV1, null));
      assertArrayEquals(new byte[]{2, 2, 2}, reopened.decrypt(underV2, null));
    }
  }

  @Test
  void wrongCurrentPassphraseIsRejected() {
    final Path keystore = tempDir.resolve("keystore.json");
    LocalKeyring.bootstrap(keystore, "real".toCharArray(), FAST).close();
    assertThrows(WrongPassphraseException.class, () ->
        RootKeyRotation.changePassphrase(keystore, "bogus".toCharArray(), "whatever".toCharArray(), FAST));
  }
}
