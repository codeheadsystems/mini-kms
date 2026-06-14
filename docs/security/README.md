# Security review notes

These notes accompany a security review of mini-kms. They exist for the same
reason the rest of the project does: **to teach.** Each one documents a real
weakness, the threat it poses, a concrete fix, and *why the fix works* — the kind
of reasoning a production KMS team goes through.

> mini-kms is an educational project. The review found **no Critical or High
> severity, remotely-exploitable vulnerabilities**: the crypto is sound
> (Argon2id, AES-256-GCM/AEAD, fresh random nonces), tokens are compared in
> constant time, failures are flattened to avoid oracles, and secrets stay out of
> logs and argv. The items below are the hardening gaps and integrity properties
> that separate a teaching KMS from a production one.

## Findings

| # | Severity | Issue | Status | Doc |
|---|----------|-------|--------|-----|
| 1 | Medium | Pre-authentication connection & slow-read resource exhaustion | ✅ Fixed | [01](01-pre-auth-connection-exhaustion.md) |
| 2 | Medium | Keystore metadata is not integrity-protected | ✅ Fixed | [02](02-keystore-metadata-integrity.md) |
| 3 | Low | Loopback TCP listener is reachable by every local user | Open | [03](03-loopback-tcp-local-exposure.md) |

Findings 1 and 2 have been fixed; each doc shows the before/after of the change
and points at the tests that lock it in. Finding 3 remains open (documented).

## Lower-priority / inherent risks (no code change required)

- **Offline passphrase cracking is the real-world worst case.** A stolen
  `keystore.json` lets an attacker brute-force the passphrase offline, using the
  verification token as a free oracle (`derive candidate → decrypt token →
  compare to the known constant`). Argon2id is the *only* barrier, so overall
  security collapses to passphrase entropy. Operators should use a long,
  high-entropy passphrase and protect the keystore file and its backups
  accordingly.
- **The shared tokens live as immutable `String`s** for the process lifetime, so
  unlike the passphrase (`char[]`, zeroed) they cannot be wiped and may appear in
  a heap dump. Prefer token *files* with tight permissions over environment
  variables, which are visible to child processes.
- **AES-GCM random-nonce ceiling.** A single long-lived root key, and any
  heavily-used KEK, accumulate GCM encryptions over time. At this project's scale
  the count stays far within the safe limit for random 96-bit nonces (~2^32
  messages per key), and **rotation is what keeps it that way** — which is part
  of why rotation exists.
