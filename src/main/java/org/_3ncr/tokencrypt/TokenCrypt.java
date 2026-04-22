package org._3ncr.tokencrypt;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Java implementation of the <a href="https://3ncr.org/">3ncr.org</a> v1 string
 * encryption standard.
 *
 * <p>The v1 envelope is {@code 3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>}
 * using AES-256-GCM with a 12-byte random IV and base64 without padding. The
 * envelope is agnostic of how the 32-byte AES key was derived; pick a factory
 * based on the entropy of the input secret.
 */
public final class TokenCrypt {

    /** 3ncr.org v1 envelope header. */
    public static final String HEADER_V1 = "3ncr.org/1#";

    private static final int AES_KEY_SIZE = 32;
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE = 16;
    private static final int TAG_BITS = TAG_SIZE * 8;

    // 3ncr.org recommended Argon2id parameters (https://3ncr.org/1/ — Key
    // Derivation section).
    private static final int ARGON2ID_MEMORY_KIB = 19456;
    private static final int ARGON2ID_TIME_COST = 2;
    private static final int ARGON2ID_PARALLELISM = 1;
    private static final int ARGON2ID_MIN_SALT_BYTES = 16;

    private static final SecureRandom RNG = new SecureRandom();

    private final SecretKeySpec keySpec;

    private TokenCrypt(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }
        if (key.length != AES_KEY_SIZE) {
            throw new IllegalArgumentException(
                "key must be exactly " + AES_KEY_SIZE + " bytes, got " + key.length);
        }
        this.keySpec = new SecretKeySpec(key.clone(), "AES");
    }

    /**
     * Build a {@code TokenCrypt} from a raw 32-byte AES-256 key.
     *
     * <p>Use this when your secret is already high-entropy and exactly 32 bytes
     * (for example, loaded from a key-management service).
     */
    public static TokenCrypt fromRawKey(byte[] key) {
        return new TokenCrypt(key);
    }

    /**
     * Derive the AES key from a high-entropy secret via a single SHA3-256 hash.
     *
     * <p>Suitable for random pre-shared keys, UUIDs, or long random API tokens —
     * inputs that already carry at least 128 bits of unique entropy. For
     * low-entropy inputs such as user passwords, prefer
     * {@link #fromArgon2id(byte[], byte[])}.
     */
    public static TokenCrypt fromSha3(byte[] secret) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA3-256 not available", e);
        }
        return new TokenCrypt(md.digest(secret));
    }

    /** Convenience overload: UTF-8 encodes {@code secret} before hashing. */
    public static TokenCrypt fromSha3(String secret) {
        return fromSha3(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Derive the AES key from a low-entropy secret via Argon2id using the
     * 3ncr.org v1 recommended parameters (m=19456 KiB, t=2, p=1).
     *
     * <p>{@code salt} must be at least 16 bytes. For deterministic derivation
     * across implementations, pass the same salt.
     */
    public static TokenCrypt fromArgon2id(byte[] secret, byte[] salt) {
        if (salt == null || salt.length < ARGON2ID_MIN_SALT_BYTES) {
            int got = (salt == null) ? 0 : salt.length;
            throw new IllegalArgumentException(
                "salt must be at least " + ARGON2ID_MIN_SALT_BYTES + " bytes, got " + got);
        }
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(ARGON2ID_MEMORY_KIB)
            .withIterations(ARGON2ID_TIME_COST)
            .withParallelism(ARGON2ID_PARALLELISM)
            .withSalt(salt)
            .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] key = new byte[AES_KEY_SIZE];
        gen.generateBytes(secret, key);
        return new TokenCrypt(key);
    }

    /** Convenience overload: UTF-8 encodes {@code secret} before hashing. */
    public static TokenCrypt fromArgon2id(String secret, byte[] salt) {
        return fromArgon2id(secret.getBytes(StandardCharsets.UTF_8), salt);
    }

    /**
     * Derive the AES key via PBKDF2-HMAC-SHA3-256 (legacy KDF).
     *
     * <p>Kept for backward compatibility with data encrypted by earlier
     * 3ncr.org libraries. New callers should use
     * {@link #fromArgon2id(byte[], byte[])} for passwords or
     * {@link #fromRawKey(byte[])} / {@link #fromSha3(byte[])} for high-entropy
     * secrets. See <a href="https://3ncr.org/1/#kdf">the v1 spec</a>.
     *
     * @deprecated legacy KDF; use {@link #fromArgon2id(byte[], byte[])} for
     *     passwords or {@link #fromRawKey(byte[])} / {@link #fromSha3(byte[])}
     *     for high-entropy secrets.
     */
    @Deprecated
    public static TokenCrypt fromPbkdf2Sha3(byte[] secret, byte[] salt, int iterations) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA3Digest(256));
        gen.init(secret, salt, iterations);
        KeyParameter kp = (KeyParameter) gen.generateDerivedParameters(AES_KEY_SIZE * 8);
        return new TokenCrypt(kp.getKey());
    }

    /** Convenience overload: UTF-8 encodes {@code secret} and {@code salt}. */
    @Deprecated
    public static TokenCrypt fromPbkdf2Sha3(String secret, String salt, int iterations) {
        return fromPbkdf2Sha3(
            secret.getBytes(StandardCharsets.UTF_8),
            salt.getBytes(StandardCharsets.UTF_8),
            iterations);
    }

    /** Encrypt a UTF-8 string and return a {@code 3ncr.org/1#...} value. */
    public String encrypt3ncr(String plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext must not be null");
        }
        byte[] iv = new byte[IV_SIZE];
        RNG.nextBytes(iv);
        byte[] ctAndTag;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(TAG_BITS, iv));
            ctAndTag = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
        byte[] buf = new byte[IV_SIZE + ctAndTag.length];
        System.arraycopy(iv, 0, buf, 0, IV_SIZE);
        System.arraycopy(ctAndTag, 0, buf, IV_SIZE, ctAndTag.length);
        return HEADER_V1 + Base64.getEncoder().withoutPadding().encodeToString(buf);
    }

    /**
     * If {@code value} has the {@code 3ncr.org/1#} header, decrypt it;
     * otherwise return it unchanged.
     *
     * <p>This makes it safe to route every configuration value through
     * {@code decryptIf3ncr} regardless of whether it was encrypted.
     *
     * @throws TokenCryptException if the value is a 3ncr token but cannot be
     *     decoded or authenticated.
     */
    public String decryptIf3ncr(String value) {
        if (value == null) {
            throw new IllegalArgumentException("value must not be null");
        }
        if (!value.startsWith(HEADER_V1)) {
            return value;
        }
        return decrypt(value.substring(HEADER_V1.length()));
    }

    private String decrypt(String body) {
        byte[] buf;
        try {
            // Spec emits no padding; JDK Basic decoder accepts both for robustness.
            buf = Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new TokenCryptException("invalid base64 payload", e);
        }
        if (buf.length < IV_SIZE + TAG_SIZE) {
            throw new TokenCryptException("truncated 3ncr token");
        }
        byte[] iv = Arrays.copyOfRange(buf, 0, IV_SIZE);
        byte[] ctAndTag = Arrays.copyOfRange(buf, IV_SIZE, buf.length);
        byte[] plaintext;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(TAG_BITS, iv));
            plaintext = cipher.doFinal(ctAndTag);
        } catch (GeneralSecurityException e) {
            throw new TokenCryptException("authentication tag verification failed", e);
        }
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}
