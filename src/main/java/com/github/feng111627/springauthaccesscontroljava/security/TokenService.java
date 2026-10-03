package com.github.feng111627.springauthaccesscontroljava.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

/**
 * Issues and verifies compact HMAC-SHA256 signed tokens.
 *
 * <p>Wire format: {@code base64url(header).base64url(payload).base64url(signature)},
 * where the signature covers the first two segments. No external JWT library is
 * required. Every verification failure maps to exactly one distinguishable
 * {@link TokenError}, so callers never report an ambiguous "invalid token".
 */
@Component
public class TokenService {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DECODER = Base64.getUrlDecoder();

    private final byte[] signingKey;
    private final long accessTtlMillis;
    private final long refreshTtlMillis;
    private final TimeSource timeSource;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public TokenService(
            @Value("${app.security.token-secret}") String secret,
            @Value("${app.security.access-token-ttl-millis}") long accessTtlMillis,
            @Value("${app.security.refresh-token-ttl-millis}") long refreshTtlMillis,
            TimeSource timeSource) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException(
                    "app.security.token-secret must be configured with at least 32 bytes");
        }
        this.signingKey = secret.getBytes(StandardCharsets.UTF_8);
        this.accessTtlMillis = accessTtlMillis;
        this.refreshTtlMillis = refreshTtlMillis;
        this.timeSource = timeSource;
    }

    public TokenPair issue(String subject, long epoch) {
        long now = timeSource.nowMillis();
        String access = sign(subject, TokenType.ACCESS, now, now + accessTtlMillis, epoch);
        String refresh = sign(subject, TokenType.REFRESH, now, now + refreshTtlMillis, epoch);
        return new TokenPair(access, refresh, accessTtlMillis, refreshTtlMillis);
    }

    public String issueOne(String subject, TokenType type, long epoch) {
        long now = timeSource.nowMillis();
        long ttl = type == TokenType.ACCESS ? accessTtlMillis : refreshTtlMillis;
        return sign(subject, type, now, now + ttl, epoch);
    }

    private String sign(String subject, TokenType type, long iat, long exp, long epoch) {
        try {
            ObjectNode header = objectMapper.createObjectNode();
            header.put("alg", "HS256");
            header.put("typ", "TKN");

            ObjectNode body = objectMapper.createObjectNode();
            body.put("sub", subject);
            body.put("type", type.name());
            body.put("iat", iat);
            body.put("exp", exp);
            body.put("epoch", epoch);
            body.put("jti", newJti());

            String headerSegment = encode(header.toString().getBytes(StandardCharsets.UTF_8));
            String bodySegment = encode(body.toString().getBytes(StandardCharsets.UTF_8));
            String signingInput = headerSegment + "." + bodySegment;
            String signatureSegment = encode(hmac(signingInput));
            return signingInput + "." + signatureSegment;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign token", e);
        }
    }

    /**
     * Verifies a token against the expected type.
     *
     * @throws TokenException with one of MALFORMED, SIGNATURE_INVALID,
     *         EXPIRED, WRONG_TYPE when the token cannot be accepted
     */
    public TokenPayload verify(String token, TokenType expectedType) {
        if (token == null || token.isBlank()) {
            throw new TokenException(TokenError.MALFORMED);
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank()
                || parts[2].isBlank()) {
            throw new TokenException(TokenError.MALFORMED);
        }
        String signingInput = parts[0] + "." + parts[1];

        byte[] providedSignature;
        try {
            providedSignature = B64URL_DECODER.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new TokenException(TokenError.MALFORMED);
        }

        // Signature is checked before any payload interpretation: a tampered
        // envelope (payload or signature altered) is SIGNATURE_INVALID.
        if (!constantTimeEquals(hmac(signingInput), providedSignature)) {
            throw new TokenException(TokenError.SIGNATURE_INVALID);
        }

        JsonNode body;
        try {
            byte[] rawHeader = B64URL_DECODER.decode(parts[0]);
            byte[] rawBody = B64URL_DECODER.decode(parts[1]);
            JsonNode header = objectMapper.readTree(rawHeader);
            body = objectMapper.readTree(rawBody);
            if (!"HS256".equals(header.path("alg").asText())
                    || !body.hasNonNull("sub")
                    || !body.hasNonNull("type")
                    || !body.hasNonNull("iat")
                    || !body.hasNonNull("exp")
                    || !body.hasNonNull("epoch")
                    || !body.hasNonNull("jti")) {
                throw new TokenException(TokenError.MALFORMED);
            }
        } catch (TokenException e) {
            throw e;
        } catch (Exception e) {
            throw new TokenException(TokenError.MALFORMED);
        }

        long now = timeSource.nowMillis();
        long exp = body.get("exp").asLong();
        if (now >= exp) {
            throw new TokenException(TokenError.EXPIRED);
        }

        TokenType actualType;
        try {
            actualType = TokenType.valueOf(body.get("type").asText());
        } catch (IllegalArgumentException e) {
            throw new TokenException(TokenError.MALFORMED);
        }
        if (actualType != expectedType) {
            // A refresh token presented to a resource API (or vice versa).
            throw new TokenException(TokenError.WRONG_TYPE);
        }

        return new TokenPayload(
                body.get("sub").asText(),
                actualType,
                body.get("iat").asLong(),
                exp,
                body.get("epoch").asLong(),
                body.get("jti").asText());
    }

    private byte[] hmac(String input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
            return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failure", e);
        }
    }

    private static String encode(byte[] bytes) {
        return B64URL.encodeToString(bytes);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    private String newJti() {
        return UUID.randomUUID().toString();
    }
}
