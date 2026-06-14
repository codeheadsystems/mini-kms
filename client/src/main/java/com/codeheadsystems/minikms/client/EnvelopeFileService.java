package com.codeheadsystems.minikms.client;

import com.codeheadsystems.minikms.crypto.AesGcm;
import com.codeheadsystems.minikms.kms.DataKey;
import java.util.Arrays;
import javax.crypto.SecretKey;

/**
 * End-to-end envelope encryption of a blob, the way a real client would do it.
 *
 * <p>Encrypt:
 * <ol>
 *   <li>ask the KMS for a fresh data key ({@code GenerateDataKey}),</li>
 *   <li>encrypt the data <em>locally</em> with the plaintext DEK (fast, and the
 *       bulk data never touches the KMS),</li>
 *   <li>store the wrapped DEK alongside the ciphertext in a {@link FileEnvelope},</li>
 *   <li>zero the plaintext DEK.</li>
 * </ol>
 *
 * <p>Decrypt reverses it: read the container, ask the KMS to unwrap the DEK
 * ({@code Decrypt}), then decrypt the ciphertext locally and zero the DEK.
 *
 * <p>The AAD ("encryption context"), if supplied, binds the wrapped DEK to that
 * context: the KMS will only unwrap it when the same AAD is presented.
 */
public final class EnvelopeFileService {

  private final KmsClient client;
  private final AesGcm aesGcm = new AesGcm();

  /**
   * @param client a connected KMS client.
   */
  public EnvelopeFileService(final KmsClient client) {
    this.client = client;
  }

  /**
   * Envelope-encrypt {@code plaintext} using the default key group.
   *
   * @param plaintext the data to protect.
   * @param aad       optional encryption context bound to the wrapped DEK; may be {@code null}.
   * @return the serialized {@link FileEnvelope} container bytes.
   */
  public byte[] encrypt(final byte[] plaintext, final byte[] aad) {
    return encrypt(null, plaintext, aad);
  }

  /**
   * Envelope-encrypt {@code plaintext} using a named key group.
   *
   * @param keyId     the key group whose active version wraps the DEK (null → default).
   * @param plaintext the data to protect.
   * @param aad       optional encryption context bound to the wrapped DEK; may be {@code null}.
   * @return the serialized {@link FileEnvelope} container bytes.
   */
  public byte[] encrypt(final String keyId, final byte[] plaintext, final byte[] aad) {
    final DataKey dataKey = client.generateDataKey(keyId, aad);
    final byte[] plaintextDek = dataKey.plaintext();
    try {
      final SecretKey dek = AesGcm.toKey(plaintextDek);
      final byte[] ciphertext = aesGcm.encrypt(dek, plaintext, aad);
      return new FileEnvelope(dataKey.wrapped(), ciphertext).serialize();
    } finally {
      Arrays.fill(plaintextDek, (byte) 0);
    }
  }

  /**
   * Decrypt a container produced by {@link #encrypt}.
   *
   * @param container the serialized {@link FileEnvelope} bytes.
   * @param aad       the same encryption context used at encrypt time; may be {@code null}.
   * @return the recovered plaintext.
   */
  public byte[] decrypt(final byte[] container, final byte[] aad) {
    final FileEnvelope envelope = FileEnvelope.parse(container);
    final byte[] plaintextDek = client.decrypt(envelope.wrappedDek(), aad);
    try {
      final SecretKey dek = AesGcm.toKey(plaintextDek);
      return aesGcm.decrypt(dek, envelope.ciphertext(), aad);
    } finally {
      Arrays.fill(plaintextDek, (byte) 0);
    }
  }
}
