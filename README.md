# tokencrypt (3ncr.org)

[![Test](https://github.com/3ncr/tokencrypt-java/actions/workflows/test.yml/badge.svg)](https://github.com/3ncr/tokencrypt-java/actions/workflows/test.yml)
[![Maven Central](https://img.shields.io/maven-central/v/org._3ncr/tokencrypt.svg)](https://central.sonatype.com/artifact/org._3ncr/tokencrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[3ncr.org](https://3ncr.org/) is a standard for string encryption / decryption
(algorithms + storage format), originally intended for encrypting tokens in
configuration files but usable for any UTF-8 string. v1 uses AES-256-GCM for
authenticated encryption with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

This is the official Java implementation.

## Install

Requires JDK 17+. AES-256-GCM and SHA3-256 come from the JDK; Argon2id comes
from [Bouncy Castle](https://www.bouncycastle.org/).

Maven:

```xml
<dependency>
    <groupId>org._3ncr</groupId>
    <artifactId>tokencrypt</artifactId>
    <version>1.0.0</version>
</dependency>
```

Gradle:

```gradle
implementation 'org._3ncr:tokencrypt:1.0.0'
```

## Usage

Pick a factory based on the entropy of your secret — see the
[3ncr.org v1 KDF guidance](https://3ncr.org/1/#kdf) for the canonical
recommendation.

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key, skip the KDF and pass it directly.

```java
import org._3ncr.tokencrypt.TokenCrypt;
import java.security.SecureRandom;

byte[] key = new byte[32];
new SecureRandom().nextBytes(key);
TokenCrypt tc = TokenCrypt.fromRawKey(key);
```

For a high-entropy secret that is not already 32 bytes (e.g. a random API
token), hash it through SHA3-256:

```java
TokenCrypt tc = TokenCrypt.fromSha3("some-high-entropy-api-token");
```

### Recommended: Argon2id (passwords / low-entropy secrets)

For passwords or passphrases, use `TokenCrypt.fromArgon2id`. It uses the
parameters recommended by the [3ncr.org v1 spec](https://3ncr.org/1/#kdf)
(`m=19456 KiB, t=2, p=1`). The salt must be at least 16 bytes.

```java
import org._3ncr.tokencrypt.TokenCrypt;
import java.nio.charset.StandardCharsets;

byte[] salt = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
TokenCrypt tc = TokenCrypt.fromArgon2id("correct horse battery staple", salt);
```

### Legacy: PBKDF2-SHA3 (existing data only)

This library does not implement the legacy PBKDF2-SHA3 KDF that earlier 3ncr.org
libraries (Go, Node.js, PHP) shipped for backward compatibility. If you need to
decrypt data produced by that KDF, derive the 32-byte key with BouncyCastle's
`PKCS5S2ParametersGenerator` backed by a `SHA3Digest(256)` (or any PBKDF2-SHA3-256
implementation) and pass the result to `fromRawKey`.

### Encrypt / decrypt

```java
TokenCrypt tc = TokenCrypt.fromSha3("some-high-entropy-api-token");

String encrypted = tc.encrypt3ncr("08019215-B205-4416-B2FB-132962F9952F");
// e.g. "3ncr.org/1#pHRu..."

String decrypted = tc.decryptIf3ncr(encrypted);
```

`decryptIf3ncr` returns its input unchanged when the value does not start with
the `3ncr.org/1#` header. This makes it safe to route every configuration value
through it regardless of whether it was encrypted.

Decryption failures (bad tag, truncated input, malformed base64) throw
`TokenCryptException` (an unchecked exception).

## Cross-implementation interop

This implementation decrypts the canonical v1 envelope test vectors shared with
the [Go](https://github.com/3ncr/tokencrypt),
[Node.js](https://github.com/3ncr/nodencrypt),
[PHP](https://github.com/3ncr/tokencrypt-php),
[Python](https://github.com/3ncr/tokencrypt-python), and
[Rust](https://github.com/3ncr/tokencrypt-rust) reference libraries. The original
32-byte AES key was derived via PBKDF2-SHA3-256 with `secret = "a"`,
`salt = "b"`, `iterations = 1000`; this library only ships the modern KDFs
(raw key / SHA3-256 / Argon2id), so the test harness hardcodes the derived key
to verify envelope-level interop. See
`src/test/java/org/_3ncr/tokencrypt/TokenCryptTest.java`.

## License

MIT — see [LICENSE](LICENSE).
