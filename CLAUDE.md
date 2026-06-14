# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

mini-kms is an **educational** single-machine Key Management Service in Java: envelope
encryption with rotatable keys served to local processes over sockets. It is heavily
commented on purpose — the code is meant to be *read* to learn how a KMS works. It uses
real, sound crypto (Argon2id, AES-256-GCM/AEAD) but is explicitly not production-audited.
Keep that intent in mind: clarity and correct security reasoning matter more than features,
and comments carry real teaching weight.

## Build & test

Requires JDK 21+ (the Gradle toolchain is pinned to 21; it can auto-download via the
foojay resolver).

```bash
./gradlew build                 # compile + run ALL tests (this is the CI check)
./gradlew test                  # tests only, all modules
./gradlew :core:test            # one module
./gradlew :core:test --tests "*LocalKeyringTest"                       # one test class
./gradlew :core:test --tests "*LocalKeyringTest.rotationKeepsOldCiphertextsDecryptable"  # one method

./gradlew :server:installDist :client:installDist   # produce runnable launcher scripts
```

There is **no separate linter/formatter**; `./gradlew build` is the full gate. Tests are
JUnit 5. Note Gradle's configuration cache is on (`org.gradle.configuration-cache=true`),
so build-script changes may need `--no-configuration-cache` while iterating.

## Running it locally

Server reads the passphrase with no echo (`Console.readPassword`), or `MINIKMS_PASSPHRASE`
when there's no TTY. Both tokens come from env vars or files, **never CLI args**.

```bash
export MINIKMS_API_TOKEN="$(openssl rand -hex 32)"      # data plane
export MINIKMS_ADMIN_TOKEN="$(openssl rand -hex 32)"    # control plane
server/build/install/server/bin/server --tcp-port 9123 --keystore ~/.mini-kms/keystore.json

client/build/install/client/bin/client --tcp 127.0.0.1:9123 health    # data-plane CLI
client/build/install/client/bin/kms-admin --tcp 127.0.0.1:9123 list-keys   # control-plane CLI (admin token)
```

## Architecture

Three Gradle modules under base package `com.codeheadsystems.minikms`:

- **`core`** — all crypto + key management, with **no socket/transport/CLI code**. This
  separation is load-bearing: keep `core` free of I/O so the request handler and key
  store can be reused and swapped. Owns the wire-protocol DTOs (shared by server + client),
  the envelope formats, the keyring, and the request handler.
- **`server`** — the socket daemon (`ServerMain`); depends on `core`.
- **`client`** — `KmsClient` library plus two CLIs (`ClientMain` = data plane,
  `KeyringAdminMain` = control plane); depends on `core`.

### Two planes, two tokens

Every `RequestType` is tagged `DATA` or `CONTROL` (`RequestPlane`). `KmsRequestHandler`
(in `core`) routes by plane and validates the matching token — the **API token** for data
ops, a **separate admin token** for control ops — so a data client cannot manage keys.
Data-plane ops additionally pass through `KeyAuthorizationPolicy` per key group; the shipped
`AllowAllPolicy` permits any authenticated principal (the documented seam for per-client
authz later).

### The two seams (why the design is shaped this way)

`KmsRequestHandler` depends only on two interfaces, both implemented by `LocalKeyring`:

- `MasterKeyProvider` (data plane): `wrap/unwrap/encrypt/decrypt/keyIdOf`
- `KeyringManager` (control plane): `create/rotate/list/disable/enable/destroy`

Because each ciphertext carries its own `kek_id` *inside* the opaque blob, these signatures
are stable: a future remote/HSM-backed provider can drop in without touching request
handling. **Preserve this boundary** — don't make the handler reach past these interfaces.

### Key hierarchy (see README "Glossary" + "The key hierarchy")

`passphrase --Argon2id+salt--> root key --wraps--> KEK versions --wrap--> DEKs --AES-GCM--> data`

The root key and KEKs exist only as `byte[]` in memory and are zeroed on shutdown
(`LocalKeyring.close()`, wired via a shutdown hook in `ServerMain`). Rotation never strands
data because every blob records the exact `(group, version)` that wrapped it. `DestroyVersion`
is intentionally irreversible (crypto-shredding).

### Crypto & formats

- `crypto/AesGcm` is the **only** place raw symmetric crypto happens. Nonces are always
  fresh-random and never caller-supplied (GCM nonce reuse is catastrophic). AAD is optional
  ("encryption context") and bound but not stored.
- Three nested binary formats: `EnvelopeFormat` (version+alg+nonce+ciphertext+tag — the inner
  primitive), `KekEnvelope` (prepends `kek_id` → the client-facing blob), and the client-only
  `FileEnvelope` (`MKE1` container: wrapped DEK + file ciphertext).
- The keystore (`keystore.json`, `0600`) holds the salt, Argon2 params, a verification token,
  the root-wrapped KEKs, **and an HMAC over all metadata** (`KeystoreIntegrity`). It never
  contains a plaintext key. The MAC is now **required** on load: tampering with plaintext
  fields (e.g. flipping a version's status) is rejected, and a keystore written by older code
  without a `macBase64` field will fail to load.

### Transport & framing

Server binds loopback TCP + a Unix domain socket (`0600` in a `0700` dir); each connection
runs on a virtual thread (`KmsServer`). Protocol is **newline-delimited JSON**, one object
per line, base64 for binary, bounded per frame (`BoundedLineReader`). Connections are bounded
two ways: a `Semaphore` connection cap and an idle-timeout watchdog (a scheduled close that
unblocks a stalled read) — both configurable. `ConnectionHandler` is transport-agnostic
(sees only streams), so TCP and Unix are handled identically.

## Conventions specific to this repo

- **`core` stays I/O-free.** No sockets, files (beyond the keystore via `Keystore`), or CLI
  parsing belong there.
- **`-parameters` compilation is required** — Jackson deserializes the protocol/keystore
  **records** by constructor parameter names. Don't remove the compiler flag (set in the root
  build) or Jackson record binding breaks.
- **No oracles, no leaks.** Any AEAD/keyring failure (wrong key/AAD, disabled/destroyed/unknown
  version, malformed blob) is flattened to a single `DecryptionFailed` response. Tokens,
  passphrases, keys, and request/response bodies are never logged.
- **Secrets via env/file, never argv.** Follow the existing `resolveToken` / `readPassphrase`
  patterns; passphrases are handled as `char[]` and zeroed.
- Use `System.Logger` (already the pattern), not a third-party logging dependency.

## Docs

- `README.md` — full architecture, flow diagrams, formats, and a glossary of terms
  (KEK/DEK/AEAD/etc.).
- `docs/security/` — security-review findings with before/after fixes (connection
  exhaustion; keystore integrity) and one open item (loopback-TCP local exposure).
