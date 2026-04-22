package org._3ncr.tokencrypt;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("deprecation") // exercising the deprecated legacy PBKDF2 KDF
class TokenCryptTest {

    private static final SecureRandom RNG = new SecureRandom();

    /**
     * Canonical v1 test vectors shared across Go, Node, PHP, Python, Rust,
     * and Java implementations. Derived via PBKDF2-SHA3-256 with secret="a",
     * salt="b", iterations=1000.
     */
    private static Stream<Arguments> canonicalVectors() {
        return Stream.of(
            Arguments.of("a", "3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8"),
            Arguments.of("test", "3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc"),
            Arguments.of(
                "08019215-B205-4416-B2FB-132962F9952F",
                "3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ"),
            Arguments.of(
                "перевірка",
                "3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ"));
    }

    private static TokenCrypt legacy() {
        return TokenCrypt.fromPbkdf2Sha3("a", "b", 1000);
    }

    private static byte[] randomKey() {
        byte[] k = new byte[32];
        RNG.nextBytes(k);
        return k;
    }

    @ParameterizedTest
    @MethodSource("canonicalVectors")
    void decryptsCanonicalVector(String plaintext, String encrypted) {
        assertEquals(plaintext, legacy().decryptIf3ncr(encrypted));
    }

    @ParameterizedTest
    @MethodSource("canonicalVectors")
    void roundTripsCanonicalPlaintext(String plaintext, String ignoredEncrypted) {
        TokenCrypt tc = legacy();
        String enc = tc.encrypt3ncr(plaintext);
        assertTrue(enc.startsWith(TokenCrypt.HEADER_V1), "should start with header");
        assertEquals(plaintext, tc.decryptIf3ncr(enc));
    }

    @Test
    void roundTripsEdgeCases() {
        TokenCrypt tc = TokenCrypt.fromRawKey(randomKey());
        StringBuilder longBuf = new StringBuilder(4096);
        for (int i = 0; i < 4096; i++) {
            longBuf.append('a');
        }
        String[] cases = {
            "",
            "x",
            "hello, world",
            "08019215-B205-4416-B2FB-132962F9952F",
            "перевірка 🌍 中文 ✓",
            longBuf.toString(),
        };
        for (String p : cases) {
            String enc = tc.encrypt3ncr(p);
            assertEquals(p, tc.decryptIf3ncr(enc));
        }
    }

    @Test
    void non3ncrReturnedUnchanged() {
        TokenCrypt tc = TokenCrypt.fromRawKey(randomKey());
        String s = "plain config value";
        assertSame(s, tc.decryptIf3ncr(s));
    }

    @Test
    void emptyStringReturnedUnchanged() {
        TokenCrypt tc = TokenCrypt.fromRawKey(randomKey());
        String s = "";
        assertSame(s, tc.decryptIf3ncr(s));
    }

    @Test
    void ivUniquenessAcrossEncryptions() {
        TokenCrypt tc = TokenCrypt.fromRawKey(randomKey());
        String a = tc.encrypt3ncr("same plaintext");
        String b = tc.encrypt3ncr("same plaintext");
        assertNotEquals(a, b);
    }

    @Test
    void tamperedPayloadIsRejected() {
        TokenCrypt tc = TokenCrypt.fromRawKey(randomKey());
        String enc = tc.encrypt3ncr("sensitive value");
        String body = enc.substring(TokenCrypt.HEADER_V1.length());
        char[] chars = body.toCharArray();
        int idx = chars.length / 2;
        chars[idx] = (chars[idx] == 'A') ? 'B' : 'A';
        String tampered = TokenCrypt.HEADER_V1 + new String(chars);
        assertThrows(TokenCryptException.class, () -> tc.decryptIf3ncr(tampered));
    }

    @Test
    void truncatedPayloadIsRejected() {
        TokenCrypt tc = TokenCrypt.fromRawKey(randomKey());
        TokenCryptException ex = assertThrows(
            TokenCryptException.class,
            () -> tc.decryptIf3ncr(TokenCrypt.HEADER_V1 + "AAAA"));
        assertTrue(ex.getMessage().contains("truncated"), "message should mention truncated");
    }

    @Test
    void decoderAcceptsPaddedInput() {
        TokenCrypt tc = legacy();
        String plaintext = "a";
        String encrypted = "3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8";
        String body = encrypted.substring(TokenCrypt.HEADER_V1.length());
        int padCount = (4 - body.length() % 4) % 4;
        StringBuilder sb = new StringBuilder(TokenCrypt.HEADER_V1).append(body);
        for (int i = 0; i < padCount; i++) {
            sb.append('=');
        }
        assertEquals(plaintext, tc.decryptIf3ncr(sb.toString()));
    }

    @Test
    void encoderEmitsNoPadding() {
        TokenCrypt tc = TokenCrypt.fromRawKey(randomKey());
        String enc = tc.encrypt3ncr("some value");
        assertTrue(!enc.contains("="), "encoded output must not contain base64 padding");
    }

    @Test
    void fromSha3RoundTrip() {
        TokenCrypt tc = TokenCrypt.fromSha3("some-high-entropy-api-token");
        String enc = tc.encrypt3ncr("hello");
        assertEquals("hello", tc.decryptIf3ncr(enc));
    }

    @Test
    void fromSha3BytesAndStringAgree() {
        String secret = "some-high-entropy-api-token";
        TokenCrypt a = TokenCrypt.fromSha3(secret);
        TokenCrypt b = TokenCrypt.fromSha3(secret.getBytes(StandardCharsets.UTF_8));
        String enc = a.encrypt3ncr("hello");
        assertEquals("hello", b.decryptIf3ncr(enc));
    }

    @Test
    void fromArgon2idRoundTrip() {
        TokenCrypt tc = TokenCrypt.fromArgon2id(
            "correct horse battery staple",
            "0123456789abcdef".getBytes(StandardCharsets.UTF_8));
        canonicalVectors().forEach(args -> {
            String p = (String) args.get()[0];
            String enc = tc.encrypt3ncr(p);
            assertEquals(p, tc.decryptIf3ncr(enc));
        });
    }

    @Test
    void fromArgon2idRejectsShortSalt() {
        assertThrows(
            IllegalArgumentException.class,
            () -> TokenCrypt.fromArgon2id("secret", "short".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void fromArgon2idWrongSecretFailsToDecrypt() {
        byte[] salt = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        TokenCrypt right = TokenCrypt.fromArgon2id("right secret", salt);
        TokenCrypt wrong = TokenCrypt.fromArgon2id("wrong secret", salt);
        String enc = right.encrypt3ncr("hello");
        assertThrows(TokenCryptException.class, () -> wrong.decryptIf3ncr(enc));
    }

    @Test
    void fromRawKeyRejectsWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> TokenCrypt.fromRawKey(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> TokenCrypt.fromRawKey(new byte[33]));
        assertThrows(IllegalArgumentException.class, () -> TokenCrypt.fromRawKey(new byte[0]));
    }

    @Test
    void rawKeyInputIsDefensivelyCopied() {
        byte[] key = randomKey();
        byte[] original = Arrays.copyOf(key, key.length);
        TokenCrypt tc = TokenCrypt.fromRawKey(key);
        Arrays.fill(key, (byte) 0);
        String enc = assertDoesNotThrow(() -> tc.encrypt3ncr("hello"));
        TokenCrypt same = TokenCrypt.fromRawKey(original);
        assertEquals("hello", same.decryptIf3ncr(enc));
    }
}
