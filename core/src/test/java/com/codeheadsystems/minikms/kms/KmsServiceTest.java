package com.codeheadsystems.minikms.kms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.codeheadsystems.minikms.crypto.AeadException;
import com.codeheadsystems.minikms.crypto.AesGcm;
import com.codeheadsystems.minikms.keyring.LocalKeyring;
import com.codeheadsystems.minikms.master.Argon2Settings;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KmsServiceTest {

  private static final Argon2Settings FAST = new Argon2Settings(2048, 1, 1);

  @TempDir
  Path tempDir;

  private LocalKeyring keyring;
  private KmsService kms;

  @BeforeEach
  void setUp() {
    keyring = LocalKeyring.bootstrap(tempDir.resolve("ks.json"), "pw".toCharArray(), FAST);
    kms = new KmsService(keyring);
  }

  @AfterEach
  void tearDown() {
    keyring.close();
  }

  @Test
  void generateDataKeyReturnsDistinctPlaintextAndWrapped() {
    final DataKey dataKey = kms.generateDataKey(null, null);
    assertEquals(AesGcm.KEY_LENGTH_BYTES, dataKey.plaintext().length);
    assertFalse(Arrays.equals(dataKey.plaintext(), dataKey.wrapped()));
  }

  @Test
  void generatedDataKeyUnwrapsBackToPlaintext() {
    final DataKey dataKey = kms.generateDataKey(null, null);
    assertArrayEquals(dataKey.plaintext(), kms.decrypt(dataKey.wrapped(), null));
  }

  @Test
  void encryptThenDecryptRoundTrips() {
    final byte[] secret = "small secret".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(secret, kms.decrypt(kms.encrypt(null, secret, null), null));
  }

  @Test
  void encryptionContextMustMatchToDecrypt() {
    final byte[] ciphertext = kms.encrypt(null, new byte[]{1}, "ctx-A".getBytes(StandardCharsets.UTF_8));
    assertThrows(AeadException.class, () ->
        kms.decrypt(ciphertext, "ctx-B".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void reEncryptMovesBlobToDestinationGroupActiveVersion() {
    keyring.createKeyGroup("archive");
    final byte[] underDefault = kms.encrypt(null, new byte[]{5, 6, 7}, null);
    assertEquals("default", kms.keyIdOf(underDefault).keyGroupId());

    final byte[] underArchive = kms.reEncrypt(underDefault, "archive", null);
    assertEquals("archive", kms.keyIdOf(underArchive).keyGroupId());
    assertArrayEquals(new byte[]{5, 6, 7}, kms.decrypt(underArchive, null));
  }

  @Test
  void reEncryptAfterRotationLandsOnNewVersion() {
    final byte[] underV1 = kms.encrypt(null, new byte[]{9}, null);
    keyring.rotateKeyGroup("default");
    final byte[] underV2 = kms.reEncrypt(underV1, "default", null);
    assertEquals(2, kms.keyIdOf(underV2).version());
    assertArrayEquals(new byte[]{9}, kms.decrypt(underV2, null));
  }
}
