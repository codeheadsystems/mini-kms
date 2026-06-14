package com.codeheadsystems.minikms.keyring;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Integrity protection for the keystore metadata document.
 *
 * <p>Only the KEK <em>material</em> is encrypted; the fields around it — each
 * version's {@code status}, the active-version pointer, the key-group layout, the
 * salt and the Argon2 parameters — would otherwise be unauthenticated plaintext.
 * Without a MAC, anyone able to write {@code keystore.json} could (for example)
 * flip a {@code DISABLED} version back to {@code ENABLED} to resurrect a retired
 * key, or splice a wrapped KEK into a different slot, and the change would be
 * accepted silently on load.
 *
 * <p>This class computes an HMAC-SHA256 over a canonical encoding of every
 * security-relevant field, keyed by a value <em>derived from the root key</em>
 * (domain-separated from the key's encryption use). On load the tag is recomputed
 * and compared in constant time; any mismatch — or a missing tag — means the
 * metadata is untrustworthy and the keystore is rejected. Because the MAC key is
 * derived from the root key, only the holder of the correct passphrase can
 * produce a valid tag.
 *
 * <p>Note that the salt and Argon2 parameters are <em>also</em> implicitly
 * protected by the existing verification token: altering them changes the derived
 * root key, so the token no longer decrypts. The MAC's unique contribution is
 * authenticating the fields that do <em>not</em> feed key derivation — statuses,
 * the active-version pointer, the version layout, and which wrapped KEK lives in
 * which slot.
 */
final class KeystoreIntegrity {

  private static final String MAC_ALGORITHM = "HmacSHA256";

  /** Domain-separation label so the MAC key is independent of the AES use of the root key. */
  private static final byte[] MAC_KEY_LABEL =
      "mini-kms/keystore-integrity/v1".getBytes(StandardCharsets.UTF_8);

  private KeystoreIntegrity() {
  }

  /**
   * Compute the metadata MAC (base64) under a key derived from {@code rootKey}.
   * The {@code macBase64} field of {@code metadata} is ignored (it is the output,
   * not an input).
   */
  static String computeMac(final KeystoreMetadata metadata, final byte[] rootKey) {
    final byte[] macKey = deriveMacKey(rootKey);
    try {
      final Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(new SecretKeySpec(macKey, MAC_ALGORITHM));
      return Base64.getEncoder().encodeToString(mac.doFinal(canonicalBytes(metadata)));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("failed to compute keystore MAC", e);
    } finally {
      Arrays.fill(macKey, (byte) 0);
    }
  }

  /**
   * Verify the metadata MAC, rejecting a missing or incorrect tag.
   *
   * @throws KeyringException if the metadata is unauthenticated or has been tampered with.
   */
  static void verify(final KeystoreMetadata metadata, final byte[] rootKey) {
    if (metadata.macBase64() == null) {
      throw new KeyringException("keystore is missing its integrity tag (unauthenticated metadata)");
    }
    final byte[] expected = Base64.getDecoder().decode(metadata.macBase64());
    final byte[] actual = Base64.getDecoder().decode(computeMac(metadata, rootKey));
    if (!MessageDigest.isEqual(expected, actual)) {
      throw new KeyringException("keystore integrity check failed: metadata has been tampered with");
    }
  }

  /** Derive a MAC key from the root key via HMAC (a PRF), keeping it distinct from encryption use. */
  private static byte[] deriveMacKey(final byte[] rootKey) {
    try {
      final Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(new SecretKeySpec(rootKey, MAC_ALGORITHM));
      return mac.doFinal(MAC_KEY_LABEL);
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("failed to derive keystore MAC key", e);
    }
  }

  /**
   * Deterministically encode every authenticated field. Length-prefixed strings
   * and fixed-width numbers make the encoding unambiguous (no field-boundary
   * confusion); the {@code macBase64} field is deliberately excluded.
   */
  private static byte[] canonicalBytes(final KeystoreMetadata metadata) {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (DataOutputStream data = new DataOutputStream(out)) {
      data.writeInt(metadata.formatVersion());
      writeString(data, metadata.kdf());
      data.writeInt(metadata.argonMemoryKiB());
      data.writeInt(metadata.argonIterations());
      data.writeInt(metadata.argonParallelism());
      writeString(data, metadata.saltBase64());
      writeString(data, metadata.rootVerificationTokenBase64());
      data.writeInt(metadata.keyGroups().size());
      for (final KeyGroupMetadata group : metadata.keyGroups()) {
        writeString(data, group.id());
        data.writeLong(group.activeVersion());
        data.writeInt(group.versions().size());
        for (final KekVersionMetadata version : group.versions()) {
          data.writeLong(version.version());
          writeString(data, version.status());
          data.writeLong(version.createdAtEpochSec());
          writeString(data, version.wrappedKekBase64()); // null is encoded distinctly (destroyed)
        }
      }
    } catch (final IOException e) {
      throw new UncheckedIOException("failed to encode keystore metadata for MAC", e);
    }
    return out.toByteArray();
  }

  /** Write a length-prefixed UTF-8 string, distinguishing {@code null} (-1) from empty (0). */
  private static void writeString(final DataOutputStream data, final String value) throws IOException {
    if (value == null) {
      data.writeInt(-1);
      return;
    }
    final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    data.writeInt(bytes.length);
    data.write(bytes);
  }
}
