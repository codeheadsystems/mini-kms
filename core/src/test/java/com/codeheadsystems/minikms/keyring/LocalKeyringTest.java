package com.codeheadsystems.minikms.keyring;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minikms.kms.MasterKeyProvider;
import com.codeheadsystems.minikms.master.Argon2Settings;
import com.codeheadsystems.minikms.master.WrongPassphraseException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LocalKeyringTest {

  private static final Argon2Settings FAST = new Argon2Settings(2048, 1, 1);

  @TempDir
  Path tempDir;

  private LocalKeyring open(final String passphrase) {
    return LocalKeyring.bootstrap(tempDir.resolve("keystore.json"), passphrase.toCharArray(), FAST);
  }

  @Test
  void firstRunCreatesDefaultGroupWithActiveVersion1() {
    try (LocalKeyring keyring = open("pw")) {
      assertEquals(1, keyring.listKeyGroups().size());
      final KeyGroupInfo def = keyring.listKeyGroups().get(0);
      assertEquals(MasterKeyProvider.DEFAULT_KEY_GROUP, def.keyGroupId());
      assertEquals(1, def.activeVersion());
    }
  }

  @Test
  void blobRecordsKekIdAndUnwrapsRoundTrip() {
    try (LocalKeyring keyring = open("pw")) {
      final byte[] dek = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
      final byte[] wrapped = keyring.wrap(null, dek, null);
      assertEquals(MasterKeyProvider.DEFAULT_KEY_GROUP, keyring.keyIdOf(wrapped).keyGroupId());
      assertEquals(1, keyring.keyIdOf(wrapped).version());
      assertArrayEquals(dek, keyring.unwrap(wrapped, null));
    }
  }

  @Test
  void rotationKeepsOldCiphertextsDecryptable() {
    try (LocalKeyring keyring = open("pw")) {
      final byte[] underV1 = keyring.encrypt("default", new byte[]{1, 2, 3}, null);
      assertEquals(1, keyring.keyIdOf(underV1).version());

      final KeyGroupInfo rotated = keyring.rotateKeyGroup("default");
      assertEquals(2, rotated.activeVersion());

      // New encryption uses v2...
      final byte[] underV2 = keyring.encrypt("default", new byte[]{4, 5, 6}, null);
      assertEquals(2, keyring.keyIdOf(underV2).version());
      // ...but the old v1 ciphertext still decrypts.
      assertArrayEquals(new byte[]{1, 2, 3}, keyring.decrypt(underV1, null));
      assertArrayEquals(new byte[]{4, 5, 6}, keyring.decrypt(underV2, null));
    }
  }

  @Test
  void groupsAreIsolated() {
    try (LocalKeyring keyring = open("pw")) {
      keyring.createKeyGroup("billing");
      final byte[] billingBlob = keyring.encrypt("billing", new byte[]{7}, null);
      assertEquals("billing", keyring.keyIdOf(billingBlob).keyGroupId());
      assertArrayEquals(new byte[]{7}, keyring.decrypt(billingBlob, null));
    }
  }

  @Test
  void createDuplicateGroupRejected() {
    try (LocalKeyring keyring = open("pw")) {
      keyring.createKeyGroup("g");
      assertThrows(KeyringException.class, () -> keyring.createKeyGroup("g"));
    }
  }

  @Test
  void cannotDisableOrDestroyActiveVersion() {
    try (LocalKeyring keyring = open("pw")) {
      assertThrows(KeyringException.class, () -> keyring.disableVersion("default", 1));
      assertThrows(KeyringException.class, () -> keyring.destroyVersion("default", 1));
    }
  }

  @Test
  void disabledVersionCannotDecryptUntilReEnabled() {
    try (LocalKeyring keyring = open("pw")) {
      final byte[] underV1 = keyring.encrypt("default", new byte[]{1}, null);
      keyring.rotateKeyGroup("default");           // v1 -> ENABLED, v2 ACTIVE
      keyring.disableVersion("default", 1);        // v1 -> DISABLED
      assertThrows(KeyUnavailableException.class, () -> keyring.decrypt(underV1, null));
      keyring.enableVersion("default", 1);         // v1 -> ENABLED
      assertArrayEquals(new byte[]{1}, keyring.decrypt(underV1, null));
    }
  }

  @Test
  void destroyedVersionIsPermanentlyUnrecoverable() {
    try (LocalKeyring keyring = open("pw")) {
      final byte[] underV1 = keyring.encrypt("default", new byte[]{1}, null);
      keyring.rotateKeyGroup("default");
      keyring.destroyVersion("default", 1);
      assertThrows(KeyUnavailableException.class, () -> keyring.decrypt(underV1, null));
    }
  }

  @Test
  void keyringSurvivesRestartIncludingRotations() {
    final byte[] underV1;
    final byte[] underV2;
    try (LocalKeyring first = open("pw")) {
      underV1 = first.encrypt("default", new byte[]{1}, null);
      first.rotateKeyGroup("default");
      underV2 = first.encrypt("default", new byte[]{2}, null);
      first.createKeyGroup("extra");
    }
    try (LocalKeyring second = open("pw")) {
      assertArrayEquals(new byte[]{1}, second.decrypt(underV1, null));
      assertArrayEquals(new byte[]{2}, second.decrypt(underV2, null));
      assertEquals(2, second.listKeyGroups().size());
    }
  }

  @Test
  void wrongPassphraseRejectedOnRestart() {
    open("right").close();
    assertThrows(WrongPassphraseException.class, () -> open("wrong"));
  }

  @Test
  void keystoreNeverContainsAPlaintextKek() throws Exception {
    final Path keystore = tempDir.resolve("keystore.json");
    final byte[] plaintextDek;
    try (LocalKeyring keyring = LocalKeyring.bootstrap(keystore, "pw".toCharArray(), FAST)) {
      keyring.rotateKeyGroup("default");
      // The plaintext of a freshly generated, then unwrapped, data key must not be on disk.
      final byte[] wrapped = keyring.encrypt("default", new byte[]{0}, null);
      plaintextDek = keyring.unwrap(keyring.wrap("default",
          "a-distinctive-32-byte-data-key!!".getBytes(StandardCharsets.UTF_8), null), null);
      assertTrue(wrapped.length > 0);
    }
    final byte[] fileBytes = Files.readAllBytes(keystore);
    assertFalse(contains(fileBytes, plaintextDek), "no plaintext key should be in the keystore");
    assertTrue(fileBytes.length > 0);
  }

  @Test
  void tamperingWithAVersionStatusIsDetectedOnLoad() throws Exception {
    final Path keystore = tempDir.resolve("keystore.json");
    try (LocalKeyring keyring = LocalKeyring.bootstrap(keystore, "pw".toCharArray(), FAST)) {
      keyring.rotateKeyGroup("default");        // v1 -> ENABLED, v2 ACTIVE
      keyring.disableVersion("default", 1);     // v1 -> DISABLED (e.g. retired as compromised)
    }
    // An attacker with file access flips the retired key back to ENABLED.
    final String json = Files.readString(keystore);
    assertTrue(json.contains("DISABLED"));
    Files.writeString(keystore, json.replace("DISABLED", "ENABLED"));
    // The integrity MAC no longer matches the metadata, so the keystore is refused.
    final KeyringException e = assertThrows(KeyringException.class,
        () -> LocalKeyring.bootstrap(keystore, "pw".toCharArray(), FAST));
    assertTrue(e.getMessage().contains("integrity"), e.getMessage());
  }

  @Test
  void strippingTheIntegrityTagIsRejected() throws Exception {
    final Path keystore = tempDir.resolve("keystore.json");
    LocalKeyring.bootstrap(keystore, "pw".toCharArray(), FAST).close();
    // Remove the macBase64 field entirely; an unauthenticated keystore must not load.
    final com.fasterxml.jackson.databind.ObjectMapper mapper =
        new com.fasterxml.jackson.databind.ObjectMapper();
    final com.fasterxml.jackson.databind.node.ObjectNode node =
        (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(Files.readAllBytes(keystore));
    node.remove("macBase64");
    Files.write(keystore, mapper.writeValueAsBytes(node));
    assertThrows(KeyringException.class, () -> LocalKeyring.bootstrap(keystore, "pw".toCharArray(), FAST));
  }

  private static boolean contains(final byte[] haystack, final byte[] needle) {
    if (needle.length == 0) {
      return false;
    }
    outer:
    for (int i = 0; i + needle.length <= haystack.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          continue outer;
        }
      }
      return true;
    }
    return false;
  }
}
