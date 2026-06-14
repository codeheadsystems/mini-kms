package com.codeheadsystems.minikms.keyring;

import com.codeheadsystems.minikms.crypto.AeadException;
import com.codeheadsystems.minikms.crypto.AesGcm;
import com.codeheadsystems.minikms.kms.MasterKeyProvider;
import com.codeheadsystems.minikms.master.Argon2KeyDeriver;
import com.codeheadsystems.minikms.master.Argon2Settings;
import com.codeheadsystems.minikms.master.WrongPassphraseException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The single-machine keyring: an Argon2id-derived <b>root key</b> that wraps a
 * set of <b>key groups</b>, each holding versioned <b>KEKs</b>, all in memory.
 *
 * <p>It realizes <em>both</em> planes over one keyring:
 * <ul>
 *   <li>DATA PLANE ({@link MasterKeyProvider}): wrap/unwrap/encrypt/decrypt using
 *       a group's active version, with the {@link KekId} recorded in each blob.</li>
 *   <li>CONTROL PLANE ({@link KeyringManager}): create/rotate groups, manage
 *       version lifecycle.</li>
 * </ul>
 *
 * <p>Key hierarchy (none of these is ever stored in plaintext):
 * <pre>
 *   passphrase --Argon2id--&gt; root key --wraps--&gt; KEK versions --wrap--&gt; DEKs --encrypt--&gt; data
 * </pre>
 *
 * <p>The root key and every KEK live only in {@code byte[]}s that {@link #close()}
 * zeroes. Each mutation re-persists the keystore file atomically.
 */
public final class LocalKeyring implements MasterKeyProvider, KeyringManager {

  /** Known constant encrypted under the root key to detect a wrong passphrase. */
  static final byte[] VERIFICATION_CONSTANT = "mini-kms/root-verification/v2".getBytes(StandardCharsets.UTF_8);

  /** Root-key salt length in bytes (128 bits). */
  static final int SALT_LENGTH = 16;

  private final Path keystorePath;
  private final Argon2Settings argonSettings;
  private final AesGcm aesGcm = new AesGcm();
  private final SecureRandom secureRandom = new SecureRandom();

  private final byte[] rootKey;
  private final byte[] salt;
  // group id -> group state (insertion-ordered for stable listing)
  private final Map<String, GroupState> groups = new LinkedHashMap<>();
  private volatile boolean closed;

  private LocalKeyring(final Path keystorePath, final Argon2Settings argonSettings,
                       final byte[] rootKey, final byte[] salt) {
    this.keystorePath = keystorePath;
    this.argonSettings = argonSettings;
    this.rootKey = rootKey;
    this.salt = salt;
  }

  // ----------------------------------------------------------------------------------
  // Bootstrap (init new keystore, or load + verify passphrase against an existing one)
  // ----------------------------------------------------------------------------------

  /**
   * Initialize a new keystore or load and validate the passphrase against an existing one.
   *
   * @param keystorePath    keystore metadata file path.
   * @param passphrase      the passphrase (caller should zero it afterwards).
   * @param settingsForInit Argon2 parameters used only when initializing a new keystore.
   * @return a ready keyring.
   * @throws WrongPassphraseException if an existing keystore rejects the passphrase.
   */
  public static LocalKeyring bootstrap(final Path keystorePath, final char[] passphrase,
                                       final Argon2Settings settingsForInit) {
    if (Keystore.exists(keystorePath)) {
      return load(keystorePath, passphrase);
    }
    return initialize(keystorePath, passphrase, settingsForInit);
  }

  private static LocalKeyring initialize(final Path keystorePath, final char[] passphrase,
                                         final Argon2Settings settings) {
    final byte[] salt = new byte[SALT_LENGTH];
    new SecureRandom().nextBytes(salt);
    final byte[] rootKey = Argon2KeyDeriver.deriveMasterKey(passphrase, salt, settings);
    final LocalKeyring keyring = new LocalKeyring(keystorePath, settings, rootKey, salt);
    // Seed a default group with one active version so simple clients work out of the box.
    keyring.createKeyGroupInternal(DEFAULT_KEY_GROUP);
    keyring.persist();
    return keyring;
  }

  private static LocalKeyring load(final Path keystorePath, final char[] passphrase) {
    final KeystoreMetadata metadata = Keystore.load(keystorePath);
    final byte[] salt = Base64.getDecoder().decode(metadata.saltBase64());
    final byte[] rootKey = Argon2KeyDeriver.deriveMasterKey(passphrase, salt, metadata.argonSettings());
    final LocalKeyring keyring = new LocalKeyring(keystorePath, metadata.argonSettings(), rootKey, salt);
    keyring.verifyRootKey(metadata);
    keyring.verifyIntegrity(metadata);
    keyring.loadGroups(metadata);
    return keyring;
  }

  private void verifyRootKey(final KeystoreMetadata metadata) {
    final byte[] token = Base64.getDecoder().decode(metadata.rootVerificationTokenBase64());
    try {
      final byte[] recovered = aesGcm.decrypt(AesGcm.toKey(rootKey), token, null);
      if (!Arrays.equals(recovered, VERIFICATION_CONSTANT)) {
        throw failPassphrase();
      }
    } catch (final AeadException e) {
      throw failPassphrase();
    }
  }

  private WrongPassphraseException failPassphrase() {
    Arrays.fill(rootKey, (byte) 0);
    return new WrongPassphraseException("incorrect passphrase: keystore verification failed");
  }

  /** Authenticate the metadata before trusting any plaintext field (statuses, layout, etc.). */
  private void verifyIntegrity(final KeystoreMetadata metadata) {
    try {
      KeystoreIntegrity.verify(metadata, rootKey);
    } catch (final KeyringException e) {
      Arrays.fill(rootKey, (byte) 0);
      throw e;
    }
  }

  private void loadGroups(final KeystoreMetadata metadata) {
    for (final KeyGroupMetadata groupMeta : metadata.keyGroups()) {
      final GroupState group = new GroupState(groupMeta.activeVersion());
      for (final KekVersionMetadata versionMeta : groupMeta.versions()) {
        final KeyVersionStatus status = KeyVersionStatus.valueOf(versionMeta.status());
        final byte[] kek = versionMeta.wrappedKekBase64() == null
            ? null
            : aesGcm.decrypt(AesGcm.toKey(rootKey),
                Base64.getDecoder().decode(versionMeta.wrappedKekBase64()), null);
        group.versions.put(versionMeta.version(),
            new VersionState(status, versionMeta.createdAtEpochSec(), kek));
      }
      groups.put(groupMeta.id(), group);
    }
  }

  // ----------------------------------------------------------------------------------
  // DATA PLANE  (MasterKeyProvider)
  // ----------------------------------------------------------------------------------

  @Override
  public byte[] wrap(final String keyGroupId, final byte[] dek, final byte[] aad) {
    return encrypt(keyGroupId, dek, aad);
  }

  @Override
  public byte[] unwrap(final byte[] wrapped, final byte[] aad) {
    return decrypt(wrapped, aad);
  }

  @Override
  public synchronized byte[] encrypt(final String keyGroupId, final byte[] plaintext, final byte[] aad) {
    ensureOpen();
    final String groupId = groupId(keyGroupId);
    final GroupState group = requireGroup(groupId);
    final VersionState version = group.versions.get(group.activeVersion);
    if (version == null || !version.status.canEncrypt() || version.kek == null) {
      throw new KeyUnavailableException("no active key version for group " + groupId);
    }
    final byte[] inner = aesGcm.encrypt(AesGcm.toKey(version.kek), plaintext, aad);
    return new KekEnvelope(new KekId(groupId, group.activeVersion), inner).serialize();
  }

  @Override
  public synchronized byte[] decrypt(final byte[] ciphertext, final byte[] aad) {
    ensureOpen();
    final KekEnvelope envelope = parseEnvelope(ciphertext);
    final KekId kekId = envelope.kekId();
    final GroupState group = groups.get(kekId.keyGroupId());
    final VersionState version = group == null ? null : group.versions.get(kekId.version());
    if (version == null || !version.status.canDecrypt() || version.kek == null) {
      // Disabled/destroyed/unknown: do not reveal which; treat as a decryption failure.
      throw new KeyUnavailableException("key " + kekId + " is unavailable for decryption");
    }
    return aesGcm.decrypt(AesGcm.toKey(version.kek), envelope.innerEnvelope(), aad);
  }

  @Override
  public KekId keyIdOf(final byte[] blob) {
    return parseEnvelope(blob).kekId();
  }

  // ----------------------------------------------------------------------------------
  // CONTROL PLANE  (KeyringManager)
  // ----------------------------------------------------------------------------------

  @Override
  public synchronized KeyGroupInfo createKeyGroup(final String keyGroupId) {
    ensureOpen();
    if (groups.containsKey(keyGroupId)) {
      throw new KeyringException("key group already exists: " + keyGroupId);
    }
    createKeyGroupInternal(keyGroupId);
    persist();
    return infoFor(keyGroupId);
  }

  @Override
  public synchronized KeyGroupInfo rotateKeyGroup(final String keyGroupId) {
    ensureOpen();
    final GroupState group = requireGroup(keyGroupId);
    // Demote the current active version; mint a new active version.
    group.versions.get(group.activeVersion).status = KeyVersionStatus.ENABLED;
    final long newVersion = group.versions.lastKey() + 1;
    group.versions.put(newVersion,
        new VersionState(KeyVersionStatus.ACTIVE, nowEpochSec(), randomKek()));
    group.activeVersion = newVersion;
    persist();
    return infoFor(keyGroupId);
  }

  @Override
  public synchronized List<KeyGroupInfo> listKeyGroups() {
    ensureOpen();
    final List<KeyGroupInfo> result = new ArrayList<>();
    for (final String id : groups.keySet()) {
      result.add(infoFor(id));
    }
    return result;
  }

  @Override
  public synchronized void disableVersion(final String keyGroupId, final long version) {
    ensureOpen();
    final VersionState state = mutableVersion(keyGroupId, version, "disable");
    state.status = KeyVersionStatus.DISABLED;
    persist();
  }

  @Override
  public synchronized void enableVersion(final String keyGroupId, final long version) {
    ensureOpen();
    final VersionState state = requireVersion(requireGroup(keyGroupId), keyGroupId, version);
    if (state.status == KeyVersionStatus.DESTROYED) {
      throw new KeyringException("cannot enable a destroyed version: " + keyGroupId + " v" + version);
    }
    final GroupState group = groups.get(keyGroupId);
    state.status = version == group.activeVersion ? KeyVersionStatus.ACTIVE : KeyVersionStatus.ENABLED;
    persist();
  }

  @Override
  public synchronized void destroyVersion(final String keyGroupId, final long version) {
    ensureOpen();
    final VersionState state = mutableVersion(keyGroupId, version, "destroy");
    if (state.kek != null) {
      Arrays.fill(state.kek, (byte) 0);
      state.kek = null;
    }
    state.status = KeyVersionStatus.DESTROYED;
    persist();
  }

  // ----------------------------------------------------------------------------------
  // Internals
  // ----------------------------------------------------------------------------------

  private void createKeyGroupInternal(final String keyGroupId) {
    final GroupState group = new GroupState(1);
    group.versions.put(1L, new VersionState(KeyVersionStatus.ACTIVE, nowEpochSec(), randomKek()));
    groups.put(keyGroupId, group);
  }

  /** A version that is being mutated by an admin op; must exist and not be the active one. */
  private VersionState mutableVersion(final String keyGroupId, final long version, final String verb) {
    final GroupState group = requireGroup(keyGroupId);
    if (version == group.activeVersion) {
      throw new KeyringException("cannot " + verb + " the active version; rotate the group first");
    }
    return requireVersion(group, keyGroupId, version);
  }

  private GroupState requireGroup(final String keyGroupId) {
    final GroupState group = groups.get(keyGroupId);
    if (group == null) {
      throw new KeyringException("no such key group: " + keyGroupId);
    }
    return group;
  }

  private VersionState requireVersion(final GroupState group, final String keyGroupId, final long version) {
    final VersionState state = group.versions.get(version);
    if (state == null) {
      throw new KeyringException("no such version " + version + " in group " + keyGroupId);
    }
    return state;
  }

  private KeyGroupInfo infoFor(final String keyGroupId) {
    final GroupState group = groups.get(keyGroupId);
    final List<KekVersionInfo> versions = new ArrayList<>();
    group.versions.forEach((v, state) ->
        versions.add(new KekVersionInfo(v, state.status, state.createdAtEpochSec)));
    return new KeyGroupInfo(keyGroupId, group.activeVersion, versions);
  }

  private byte[] randomKek() {
    final byte[] kek = new byte[AesGcm.KEY_LENGTH_BYTES];
    secureRandom.nextBytes(kek);
    return kek;
  }

  private KekEnvelope parseEnvelope(final byte[] ciphertext) {
    try {
      return KekEnvelope.parse(ciphertext);
    } catch (final IllegalArgumentException e) {
      // Malformed blob; treat as a decryption failure rather than leaking structure.
      throw new KeyUnavailableException("unparseable ciphertext");
    }
  }

  private static String groupId(final String requested) {
    return requested == null || requested.isBlank() ? DEFAULT_KEY_GROUP : requested;
  }

  private static long nowEpochSec() {
    return System.currentTimeMillis() / 1000L;
  }

  private void ensureOpen() {
    if (closed) {
      throw new IllegalStateException("keyring is closed");
    }
  }

  /** Serialize the whole keyring to the keystore file, wrapping each KEK under the root key. */
  private void persist() {
    final List<KeyGroupMetadata> groupMetas = new ArrayList<>();
    groups.forEach((id, group) -> {
      final List<KekVersionMetadata> versionMetas = new ArrayList<>();
      group.versions.forEach((v, state) -> versionMetas.add(new KekVersionMetadata(
          v,
          state.status.name(),
          state.createdAtEpochSec,
          state.kek == null
              ? null
              : Base64.getEncoder().encodeToString(aesGcm.encrypt(AesGcm.toKey(rootKey), state.kek, null)))));
      groupMetas.add(new KeyGroupMetadata(id, group.activeVersion, versionMetas));
    });

    final byte[] verificationToken = aesGcm.encrypt(AesGcm.toKey(rootKey), VERIFICATION_CONSTANT, null);
    final KeystoreMetadata unsigned = new KeystoreMetadata(
        KeystoreMetadata.FORMAT_VERSION_2,
        KeystoreMetadata.KDF_ARGON2ID,
        argonSettings.memoryKiB(),
        argonSettings.iterations(),
        argonSettings.parallelism(),
        Base64.getEncoder().encodeToString(salt),
        Base64.getEncoder().encodeToString(verificationToken),
        groupMetas,
        null);
    // Sign the whole document so offline tampering of plaintext metadata is detected on load.
    final KeystoreMetadata signed = unsigned.withMac(KeystoreIntegrity.computeMac(unsigned, rootKey));
    Keystore.save(keystorePath, signed);
  }

  @Override
  public synchronized void close() {
    closed = true;
    Arrays.fill(rootKey, (byte) 0);
    for (final GroupState group : groups.values()) {
      for (final VersionState state : group.versions.values()) {
        if (state.kek != null) {
          Arrays.fill(state.kek, (byte) 0);
        }
      }
    }
  }

  /** In-memory state for one key group. */
  private static final class GroupState {
    private long activeVersion;
    private final TreeMap<Long, VersionState> versions = new TreeMap<>();

    GroupState(final long activeVersion) {
      this.activeVersion = activeVersion;
    }
  }

  /** In-memory state for one KEK version. {@code kek} is null once destroyed. */
  private static final class VersionState {
    private KeyVersionStatus status;
    private final long createdAtEpochSec;
    private byte[] kek;

    VersionState(final KeyVersionStatus status, final long createdAtEpochSec, final byte[] kek) {
      this.status = status;
      this.createdAtEpochSec = createdAtEpochSec;
      this.kek = kek;
    }
  }
}
