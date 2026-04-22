package org._3ncr.tokencrypt;

/**
 * Thrown when a {@code 3ncr.org/1#...} value cannot be decoded or decrypted
 * (malformed base64, truncated payload, or authentication tag mismatch).
 */
public class TokenCryptException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public TokenCryptException(String message) {
        super(message);
    }

    public TokenCryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
