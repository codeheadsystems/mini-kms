package com.codeheadsystems.minikms.keyring;

import com.codeheadsystems.minikms.crypto.AeadException;
import com.codeheadsystems.minikms.crypto.AesGcm;
import com.codeheadsystems.minikms.master.Argon2KeyDeriver;
import com.codeheadsystems.minikms.master.Argon2Settings;
import com.codeheadsystems.minikms.master.WrongPassphraseException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * CONTROL PLANE (offline) — rotate the root key by changing the passphrase.
 *
 * <p>This re-derives a new root key from a new passphrase (and a fresh salt) and
 * re-wraps the <em>entire keyring</em> — every KEK version and the verification
 * token — under it. Key group ids, version numbers, and statuses are unchanged,
 * so <b>no existing ciphertext is affected</b>: a client's stored blobs still
 * name the same {@link KekId} and still decrypt.
 *
 * <p>It is deliberately an <b>offline file transform</b>: it reads the keystore,
 * rewrites it, and never runs inside the serving process or accepts a passphrase
 * over the network. Run it while the server is stopped.
 */
public final class RootKeyRotation {

  private RootKeyRotation() {
  }

  /**
   * Change the keystore passphrase, re-wrapping the keyring under a new root key.
   *
   * @param keystorePath  the keystore metadata file.
   * @param oldPassphrase the current passphrase (verified; zeroed by caller).
   * @param newPassphrase the new passphrase (zeroed by caller).
   * @param newSettings   Argon2 parameters for the new root key (e.g. {@link Argon2Settings#defaults()}).
   * @throws WrongPassphraseException if the old passphrase is incorrect.
   */
  public static void changePassphrase(final Path keystorePath, final char[] oldPassphrase,
                                      final char[] newPassphrase, final Argon2Settings newSettings) {
    final AesGcm aesGcm = new AesGcm();
    final KeystoreMetadata metadata = Keystore.load(keystorePath);

    // 1. Derive + verify the old root key.
    final byte[] oldSalt = Base64.getDecoder().decode(metadata.saltBase64());
    final byte[] oldRoot = Argon2KeyDeriver.deriveMasterKey(oldPassphrase, oldSalt, metadata.argonSettings());
    try {
      verify(aesGcm, oldRoot, metadata.rootVerificationTokenBase64());
      // Refuse to re-wrap a tampered keystore: authenticate the metadata under the old root first.
      KeystoreIntegrity.verify(metadata, oldRoot);
    } catch (final RuntimeException e) {
      Arrays.fill(oldRoot, (byte) 0);
      throw e;
    }

    // 2. Derive the new root key from a fresh salt.
    final byte[] newSalt = new byte[LocalKeyring.SALT_LENGTH];
    new java.security.SecureRandom().nextBytes(newSalt);
    final byte[] newRoot = Argon2KeyDeriver.deriveMasterKey(newPassphrase, newSalt, newSettings);

    try {
      // 3. Re-wrap every KEK version under the new root key (ids/versions/status preserved).
      final List<KeyGroupMetadata> rewrappedGroups = new ArrayList<>();
      for (final KeyGroupMetadata group : metadata.keyGroups()) {
        final List<KekVersionMetadata> versions = new ArrayList<>();
        for (final KekVersionMetadata version : group.versions()) {
          versions.add(rewrapVersion(aesGcm, oldRoot, newRoot, version));
        }
        rewrappedGroups.add(new KeyGroupMetadata(group.id(), group.activeVersion(), versions));
      }

      // 4. New verification token under the new root key, and persist.
      final byte[] newToken = aesGcm.encrypt(AesGcm.toKey(newRoot), LocalKeyring.VERIFICATION_CONSTANT, null);
      final KeystoreMetadata unsigned = new KeystoreMetadata(
          KeystoreMetadata.FORMAT_VERSION_2,
          KeystoreMetadata.KDF_ARGON2ID,
          newSettings.memoryKiB(),
          newSettings.iterations(),
          newSettings.parallelism(),
          Base64.getEncoder().encodeToString(newSalt),
          Base64.getEncoder().encodeToString(newToken),
          rewrappedGroups,
          null);
      // Re-sign under the new root key so the rewritten keystore is authenticated too.
      final KeystoreMetadata rewritten = unsigned.withMac(KeystoreIntegrity.computeMac(unsigned, newRoot));
      Keystore.save(keystorePath, rewritten);
    } finally {
      Arrays.fill(oldRoot, (byte) 0);
      Arrays.fill(newRoot, (byte) 0);
    }
  }

  private static KekVersionMetadata rewrapVersion(final AesGcm aesGcm, final byte[] oldRoot,
                                                  final byte[] newRoot, final KekVersionMetadata version) {
    if (version.wrappedKekBase64() == null) {
      return version; // destroyed: no material to re-wrap
    }
    final byte[] kek = aesGcm.decrypt(AesGcm.toKey(oldRoot),
        Base64.getDecoder().decode(version.wrappedKekBase64()), null);
    try {
      final byte[] rewrapped = aesGcm.encrypt(AesGcm.toKey(newRoot), kek, null);
      return new KekVersionMetadata(version.version(), version.status(), version.createdAtEpochSec(),
          Base64.getEncoder().encodeToString(rewrapped));
    } finally {
      Arrays.fill(kek, (byte) 0);
    }
  }

  private static void verify(final AesGcm aesGcm, final byte[] root, final String tokenBase64) {
    try {
      final byte[] recovered = aesGcm.decrypt(AesGcm.toKey(root), Base64.getDecoder().decode(tokenBase64), null);
      if (!Arrays.equals(recovered, LocalKeyring.VERIFICATION_CONSTANT)) {
        throw new WrongPassphraseException("incorrect current passphrase");
      }
    } catch (final AeadException e) {
      throw new WrongPassphraseException("incorrect current passphrase");
    }
  }
}
