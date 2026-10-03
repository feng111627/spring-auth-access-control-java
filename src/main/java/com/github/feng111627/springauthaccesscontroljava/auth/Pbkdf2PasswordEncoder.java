package com.github.feng111627.springauthaccesscontroljava.auth;

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
 * 基于 PBKDF2-HMAC-SHA256 的密码编码器（本地无外部依赖方案）。
 * 存储格式：pbkdf2$iterations$saltBase64$hashBase64
 * 校验采用常量时间比较，避免计时侧信道。
 */
@Component
public class Pbkdf2PasswordEncoder {

    private static final String PREFIX = "pbkdf2";
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    private final int iterations;
    private final int saltLength;
    private final int hashLength;
    private final SecureRandom random = new SecureRandom();

    public Pbkdf2PasswordEncoder(@Value("${auth.password.iterations:120000}") int iterations,
                                 @Value("${auth.password.salt-length:16}") int saltLength,
                                 @Value("${auth.password.hash-length:32}") int hashLength) {
        this.iterations = iterations;
        this.saltLength = saltLength;
        this.hashLength = hashLength;
    }

    public String encode(String rawPassword) {
        byte[] salt = new byte[saltLength];
        random.nextBytes(salt);
        byte[] hash = pbkdf2(rawPassword.toCharArray(), salt, iterations, hashLength);
        Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
        return PREFIX + "$" + iterations + "$" + encoder.encodeToString(salt) + "$"
                + encoder.encodeToString(hash);
    }

    public boolean matches(String rawPassword, String stored) {
        if (rawPassword == null || stored == null) {
            return false;
        }
        String[] parts = stored.split("\\$", -1);
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return false;
        }
        try {
            int storedIterations = Integer.parseInt(parts[1]);
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] salt = decoder.decode(parts[2]);
            byte[] expected = decoder.decode(parts[3]);
            byte[] actual = pbkdf2(rawPassword.toCharArray(), salt, storedIterations, expected.length);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException | IllegalStateException ex) {
            // Base64 非法等情况一律按不匹配处理
            return false;
        }
    }

    byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLength) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength * 8);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 计算失败: " + e.getMessage(), e);
        }
    }
}
