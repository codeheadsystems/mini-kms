package com.codeheadsystems.minikms.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Stateless AES-256-GCM encryption/decryption against the JDK's built-in JCA.
 *
 * <p>This is the single place where raw symmetric crypto happens in mini-kms.
 * It produces and consumes the {@link EnvelopeFormat} so every ciphertext is
 * self-describing (version + algorithm + nonce). A fresh random 96-bit nonce is
 * generated for every encryption from a {@link SecureRandom}; reusing a nonce
 * with the same key would catastrophically break GCM, so nonces are never
 * caller-supplied.
 *
 * <p>Optional AAD (additional authenticated data, a.k.a. "encryption context")
 * is authenticated but not encrypted: decryption only succeeds if the exact same
 * AAD is supplied, which lets callers bind a ciphertext to a context.
 */
public final class AesGcm {

  /** AES key length in bytes (256 bits). */
  public static final int KEY_LENGTH_BYTES = 32;

  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final String KEY_ALGORITHM = "AES";

  private final SecureRandom secureRandom;

  /** Create an instance backed by a platform-default {@link SecureRandom}. */
  public AesGcm() {
    this(new SecureRandom());
  }

  /**
   * Create an instance with an explicit randomness source.
   *
   * @param secureRandom source of nonces; must be cryptographically strong.
   */
  public AesGcm(final SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  /**
   * Wrap a raw 256-bit key as a JCA {@link SecretKey}.
   *
   * @param keyBytes exactly 32 bytes of key material.
   * @return an AES {@link SecretKey} view over the bytes.
   */
  public static SecretKey toKey(final byte[] keyBytes) {
    if (keyBytes == null || keyBytes.length != KEY_LENGTH_BYTES) {
      throw new IllegalArgumentException("AES-256 key must be exactly " + KEY_LENGTH_BYTES + " bytes");
    }
    return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
  }

  /**
   * Encrypt plaintext under {@code key} with a fresh random nonce.
   *
   * @param key       the AES-256 key.
   * @param plaintext the data to encrypt.
   * @param aad       optional additional authenticated data; may be {@code null} or empty.
   * @return the serialized {@link EnvelopeFormat} (header + nonce + ciphertext + tag).
   */
  public byte[] encrypt(final SecretKey key, final byte[] plaintext, final byte[] aad) {
    final byte[] nonce = new byte[EnvelopeFormat.NONCE_LENGTH];
    secureRandom.nextBytes(nonce);
    try {
      final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(EnvelopeFormat.TAG_LENGTH_BITS, nonce));
      if (aad != null && aad.length > 0) {
        cipher.updateAAD(aad);
      }
      final byte[] ciphertext = cipher.doFinal(plaintext);
      return new EnvelopeFormat(EnvelopeFormat.VERSION_1, EnvelopeFormat.ALG_AES_256_GCM, nonce, ciphertext)
          .serialize();
    } catch (final GeneralSecurityException e) {
      // Encryption failing is a misconfiguration (bad key length, missing provider), not user input.
      throw new IllegalStateException("AES-GCM encryption failed", e);
    }
  }

  /**
   * Decrypt a serialized envelope under {@code key}.
   *
   * @param key            the AES-256 key.
   * @param serializedBlob the serialized {@link EnvelopeFormat}.
   * @param aad            the same AAD supplied at encryption time; may be {@code null} or empty.
   * @return the recovered plaintext.
   * @throws AeadException if authentication fails (wrong key, wrong AAD, or tampering).
   */
  public byte[] decrypt(final SecretKey key, final byte[] serializedBlob, final byte[] aad) {
    final EnvelopeFormat envelope = EnvelopeFormat.parse(serializedBlob);
    try {
      final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.DECRYPT_MODE, key,
          new GCMParameterSpec(EnvelopeFormat.TAG_LENGTH_BITS, envelope.nonce()));
      if (aad != null && aad.length > 0) {
        cipher.updateAAD(aad);
      }
      return cipher.doFinal(envelope.ciphertext());
    } catch (final GeneralSecurityException e) {
      // AEADBadTagException (a subclass) lands here: authentication failed. We do NOT
      // leak which input was wrong; the caller only learns the operation failed.
      throw new AeadException("AES-GCM authentication failed: wrong key, wrong AAD, or tampered ciphertext");
    }
  }
}
