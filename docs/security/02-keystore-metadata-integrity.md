# 02 — Keystore metadata is not integrity-protected

**Severity:** Medium (requires write access to the keystore file; defeats
tamper detection)
**Status:** ✅ Fixed (HMAC-SHA256 over the whole metadata document, keyed by a
root-derived key)

**Affected code:**
- `core/.../keyring/LocalKeyring.java` — `persist()`, `loadGroups()`, the KEK
  wraps that pass `aad = null`
- `core/.../keyring/KeystoreMetadata.java`, `KeyGroupMetadata`, `KekVersionMetadata`

## What the issue is

Only the **KEK key material** is encrypted. Everything around it is plaintext
JSON with no authentication tag, and the AES-GCM wraps bind no associated data:

```java
// LocalKeyring.persist() — the wrap carries no AAD
aesGcm.encrypt(AesGcm.toKey(rootKey), state.kek, null)   // aad == null
```

```jsonc
// keystore.json — these fields are confidentiality-free AND integrity-free
{
  "argonMemoryKiB": 65536, "argonIterations": 3, "argonParallelism": 1,
  "saltBase64": "...",
  "keyGroups": [{
    "id": "default", "activeVersion": 2,
    "versions": [
      { "version": 1, "status": "DISABLED", "wrappedKekBase64": "..." },
      { "version": 2, "status": "ACTIVE",   "wrappedKekBase64": "..." }
    ]
  }]
}
```

Because the wrap uses `aad = null`, a wrapped KEK is **not cryptographically
bound** to the `(groupId, version, status)` it sits next to. The keystore as a
whole has no MAC, so any edit to the surrounding fields is silently accepted on
load — the only thing checked is that the root key can still decrypt the
verification token.

## The threat it poses

An attacker who can **write** `keystore.json` (it is `0600`, so this means the
owning user, a mis-scoped backup/restore process, or malware running as that
user) can tamper undetectably:

- **Resurrect a disabled key.** An admin disables version 1 *because it was
  compromised*. Flipping `"status":"DISABLED"` back to `"ENABLED"` re-arms it for
  decryption — no passphrase, no detection. The control-plane lifecycle
  (`DisableVersion`) is supposed to be a real security boundary; here it is only
  as strong as a text edit. **This is the primary gap**, because `status` does not
  feed key derivation, so nothing else catches the change.
- **Relocate/splice wrapped KEKs.** Since no wrap is bound to its slot, a wrapped
  KEK can be copied into a different `(group, version)` position; it still
  decrypts (the wrap uses `aad = null`), producing key-confusion that is invisible
  until data fails to decrypt.
- **Tamper with the active-version pointer or version layout**, e.g. point a group
  at an old version so new encryption silently uses a retired key.

(Note: changing the salt or Argon2 parameters is a *different* case — those feed
key derivation, so altering them yields a different root key and the existing
verification token simply fails to decrypt. That already fails closed; it is a
denial of service, not a silent weakening. The MAC's unique contribution is
authenticating the fields that do **not** affect derivation: statuses, the active
pointer, the layout, and which wrapped KEK sits in which slot.)

The blast radius is bounded by needing file-write access — but a production KMS
treats its keystore as something that may live on shared storage, in backups, or
behind a less-trusted process, and **guarantees that any tampering is detected.**
The original code could not make that guarantee.

## The fix

**MAC the whole metadata document.** A new `KeystoreIntegrity` helper computes an
HMAC-SHA256 over a canonical encoding of *every* security-relevant field, keyed by
a value derived from the root key (domain-separated from the key's encryption use
so the MAC key and the AES key are independent). The tag is stored as a new
`macBase64` field and verified on load — a missing **or** mismatched tag is
rejected. This single mechanism covers `status`, `activeVersion`, the version
layout, and which wrapped KEK lives in which slot, all at once.

### Before

```java
// LocalKeyring.persist() — build metadata and write it; nothing authenticates it
final KeystoreMetadata metadata = new KeystoreMetadata(
    FORMAT_VERSION_2, KDF_ARGON2ID, /* argon params */, saltB64, verificationTokenB64, groupMetas);
Keystore.save(keystorePath, metadata);
```

```java
// LocalKeyring.load() — verify the passphrase, then trust every plaintext field
keyring.verifyRootKey(metadata);
keyring.loadGroups(metadata);   // statuses, layout, KEK slots all taken on faith
```

### After

```java
// LocalKeyring.persist() — build, then sign under a root-derived key
final KeystoreMetadata unsigned = new KeystoreMetadata(
    FORMAT_VERSION_2, KDF_ARGON2ID, /* argon params */, saltB64, verificationTokenB64, groupMetas, null);
final KeystoreMetadata signed = unsigned.withMac(KeystoreIntegrity.computeMac(unsigned, rootKey));
Keystore.save(keystorePath, signed);
```

```java
// LocalKeyring.load() — authenticate the metadata before trusting any field
keyring.verifyRootKey(metadata);
keyring.verifyIntegrity(metadata);   // throws KeyringException on a missing/altered tag
keyring.loadGroups(metadata);
```

```java
// KeystoreIntegrity — the MAC key is derived from the root key (a PRF), then HMAC
//                     is taken over a deterministic, length-prefixed encoding.
private static byte[] deriveMacKey(final byte[] rootKey) {
  final Mac mac = Mac.getInstance("HmacSHA256");
  mac.init(new SecretKeySpec(rootKey, "HmacSHA256"));
  return mac.doFinal("mini-kms/keystore-integrity/v1".getBytes(UTF_8)); // domain separation
}

static void verify(final KeystoreMetadata metadata, final byte[] rootKey) {
  if (metadata.macBase64() == null) {
    throw new KeyringException("keystore is missing its integrity tag (unauthenticated metadata)");
  }
  final byte[] expected = Base64.getDecoder().decode(metadata.macBase64());
  final byte[] actual = Base64.getDecoder().decode(computeMac(metadata, rootKey));
  if (!MessageDigest.isEqual(expected, actual)) { // constant-time compare
    throw new KeyringException("keystore integrity check failed: metadata has been tampered with");
  }
}
```

(`RootKeyRotation.changePassphrase` got the same treatment: it now verifies the
old MAC before re-wrapping and re-signs the rewritten keystore under the new root
key.)

A complementary hardening — binding each individual wrap with
`aad = (group‖version‖status)` instead of `null` — was considered. It is not
needed for the single-file threat model here because the document MAC already
covers each wrapped KEK *and its slot*, but it would additionally defeat splicing
between two different keystores that happen to share a root key.

## Why the fix works

HMAC is **authenticated**: the tag is a function of the key *and* every
authenticated byte. An attacker who flips a `status`, moves a wrapped KEK, or
repoints the active version changes the authenticated input but cannot recompute a
valid tag without the root key — which only exists after a correct passphrase is
supplied. Verification therefore fails closed on load (`KeyringException`) before
any altered value is acted on, and the constant-time `MessageDigest.isEqual`
compare avoids leaking how much of the tag matched. Deriving the MAC key from the
root key with a distinct label keeps it cryptographically independent of the AES
encryption use of the same key, and the length-prefixed canonical encoding makes
the authenticated bytes unambiguous (no field-boundary confusion, and `null`
encodes distinctly from empty). In short: integrity protection moves these fields
from "trusted because they're sitting in our file" to "trusted because the holder
of the root key vouched for them."

## Tests

`core/src/test/java/.../LocalKeyringTest.java` adds two cases:
`tamperingWithAVersionStatusIsDetectedOnLoad` (flip `DISABLED`→`ENABLED` in the
file, assert load is refused with an integrity error) and
`strippingTheIntegrityTagIsRejected` (remove `macBase64`, assert load is refused).
The existing round-trip, restart, and `RootKeyRotation` tests confirm legitimate
keystores still load and rotate cleanly.
