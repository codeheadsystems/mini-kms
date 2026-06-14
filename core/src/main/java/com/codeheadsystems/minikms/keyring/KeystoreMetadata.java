package com.codeheadsystems.minikms.keyring;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.codeheadsystems.minikms.master.Argon2Settings;
import java.util.List;

/**
 * The full contents of the keystore metadata file (JSON).
 *
 * <p>It holds everything needed to reconstruct the <b>root key</b> from the
 * passphrase, plus the whole <b>keyring</b> of KEK versions wrapped under that
 * root key — but never any key in plaintext:
 *
 * <ul>
 *   <li>the KDF + Argon2 parameters + per-install salt (to re-derive the root key);</li>
 *   <li>a verification token (a known constant encrypted under the root key) for
 *       fail-fast wrong-passphrase detection;</li>
 *   <li>every key group and its KEK versions, each wrapped under the root key.</li>
 * </ul>
 *
 * @param formatVersion              file format version.
 * @param kdf                        key derivation function name ({@code "argon2id"}).
 * @param argonMemoryKiB             Argon2 memory cost.
 * @param argonIterations            Argon2 time cost.
 * @param argonParallelism           Argon2 parallelism.
 * @param saltBase64                 per-install salt (base64).
 * @param rootVerificationTokenBase64 verification token (base64), encrypted under the root key.
 * @param keyGroups                  the keyring.
 * @param macBase64                  HMAC over all other fields, keyed by a root-derived key
 *                                   ({@link KeystoreIntegrity}); detects offline tampering of the
 *                                   otherwise-plaintext metadata. {@code null} only on the transient
 *                                   value used to compute the MAC itself.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KeystoreMetadata(
    int formatVersion,
    String kdf,
    int argonMemoryKiB,
    int argonIterations,
    int argonParallelism,
    String saltBase64,
    String rootVerificationTokenBase64,
    List<KeyGroupMetadata> keyGroups,
    String macBase64) {

  /** Current keystore file format version. */
  public static final int FORMAT_VERSION_2 = 2;

  /** Name of the only KDF currently supported. */
  public static final String KDF_ARGON2ID = "argon2id";

  /** @return the Argon2 cost parameters for the root key. */
  public Argon2Settings argonSettings() {
    return new Argon2Settings(argonMemoryKiB, argonIterations, argonParallelism);
  }

  /** @return a copy of this metadata carrying the given integrity tag. */
  public KeystoreMetadata withMac(final String mac) {
    return new KeystoreMetadata(formatVersion, kdf, argonMemoryKiB, argonIterations,
        argonParallelism, saltBase64, rootVerificationTokenBase64, keyGroups, mac);
  }
}
