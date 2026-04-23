# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-04-22

Initial release. Stable Java API for the
[3ncr.org v1](https://3ncr.org/1/) encryption envelope (AES-256-GCM,
12-byte random IV, 16-byte GCM tag). Requires JDK 11+.

### Added

- `TokenCrypt.fromRawKey(key)` — primary constructor for callers with a
  32-byte AES-256 key.
- `TokenCrypt.fromSha3(secret)` — single SHA3-256 hash for high-entropy
  secrets that are not already 32 bytes (random API tokens, UUIDs, etc.).
- `TokenCrypt.fromArgon2id(secret, salt)` — Argon2id KDF for
  password-strength secrets. Parameters match the
  [3ncr.org v1 spec](https://3ncr.org/1/#kdf):
  `m=19456 KiB, t=2, p=1`, 32-byte output, salt ≥ 16 bytes.
- `encrypt3ncr(plaintext)` / `decryptIf3ncr(value)` — encrypt to the
  `3ncr.org/1#…` envelope and decrypt only values that carry the header,
  passing everything else through unchanged.
- `TokenCryptException` — single (unchecked) exception class for decryption
  failures (bad tag, truncated input, malformed base64).

### Notes

- Cross-verified against the canonical v1 test vectors shared with the Go,
  Node.js, PHP, Python, and Rust reference implementations.
- Per 3ncr.org's new-language convention, the legacy PBKDF2-SHA3 KDF is
  intentionally omitted — there is no pre-existing Java data to decrypt.
  Callers needing it can derive the key with BouncyCastle's
  `PKCS5S2ParametersGenerator` (using `SHA3Digest(256)`) and pass the result
  to `fromRawKey`.

[1.0.0]: https://github.com/3ncr/tokencrypt-java/releases/tag/v1.0.0
