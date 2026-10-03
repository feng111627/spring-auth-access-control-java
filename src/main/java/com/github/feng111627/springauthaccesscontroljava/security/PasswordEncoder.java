package com.github.feng111627.springauthaccesscontroljava.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Hashes passwords with PBKDF2-HMAC-SHA256.
 *
 * <p>Stored form: {@code pbkdf2$<iterations>$<base64 salt>$<base64 hash>}.
 * Verification parses the stored parameters and compares digests in
 * constant time, so an incorrect password never takes a visibly different
 * code path from a correct one.
 */
@Component
public class PasswordEncoder {

    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final String PREFIX = "pbkdf2";
    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private final int iterations;
    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordEncoder(@Value("${app.security.pbkdf2-iterations}") int iterations) {
        if (iterations < 10_000) {
            throw new IllegalStateException("PBKDF2 iterations must be at least 10000");
        }
        this.iterations = iterations;
    }

    public String encode(String rawPassword)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        byte[] hash = pbkdf2(rawPassword.toCharArray(), salt, iterations);
        return PREFIX + "$" + iterations + "$"
                + ENCODER.encodeToString(salt) + "$"
                + ENCODER.encodeToString(hash);
    }

    public boolean matches(String rawPassword, String stored)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (rawPassword == null || stored == null) {
            return false;
        }
        String[] parts = stored.split("\\$", -1);
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return false;
        }
        int storedIterations;
        byte[] salt;
        byte[] expectedHash;
        try {
            storedIterations = Integer.parseInt(parts[1]);
            salt = DECODER.decode(parts[2]);
            expectedHash = DECODER.decode(parts[3]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] actualHash = pbkdf2(rawPassword.toCharArray(), salt, storedIterations);
        return MessageDigest.isEqual(actualHash, expectedHash);
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
}
