package com.github.feng111627.springauthaccesscontroljava.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.springauthaccesscontroljava.config.AuthProperties;
import com.github.feng111627.springauthaccesscontroljava.config.MutableClock;
import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 令牌签发与校验（HMAC-SHA256，紧凑序列化三段式）。
 * <p>
 * 令牌结构：base64url(header).base64url(payload).base64url(HMAC_SHA256(前两段))
 * <ul>
 *   <li>header = {"alg":"HS256","typ":"at+jwt|rt+jwt"}</li>
 *   <li>payload = {sub,jti,iat,exp,ver}，不含角色/权限（每次请求实时读取）</li>
 * </ul>
 * 校验失败原因严格区分（固定优先级，结果确定）：
 * <ol>
 *   <li>结构/编码/字段无法解析 → MALFORMED_TOKEN</li>
 *   <li>alg/typ 不认识 → UNSUPPORTED_TOKEN</li>
 *   <li>签名不匹配（任何篡改）→ BAD_TOKEN_SIGNATURE</li>
 *   <li>类型与场景不符 → WRONG_TOKEN_TYPE</li>
 *   <li>已过期 → TOKEN_EXPIRED</li>
 * </ol>
 * 账号停用/令牌版本吊销不在此处，由调用方结合用户实时状态判定。
 */
@Service
public class TokenService {

    private static final String ALGORITHM = "HmacSHA256";
    private static final String ALG_NAME = "HS256";
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AuthProperties properties;
    private final MutableClock clock;

    public TokenService(AuthProperties properties, MutableClock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public String issue(User user, TokenType type) {
        long now = clock.instant().getEpochSecond();
        Duration ttl = type == TokenType.ACCESS
                ? properties.getAccessTokenTtl()
                : properties.getRefreshTokenTtl();
        long exp = now + ttl.getSeconds();

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", ALG_NAME);
        header.put("typ", type.headerType());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", user.getUsername());
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("iat", now);
        payload.put("exp", exp);
        payload.put("ver", user.getTokenVersion());

        String headerPart = encode(toJson(header));
        String payloadPart = encode(toJson(payload));
        String signingInput = headerPart + "." + payloadPart;
        String signaturePart = encode(hmac(signingInput.getBytes(StandardCharsets.UTF_8)));
        return signingInput + "." + signaturePart;
    }

    public TokenPayload verify(String token, TokenType expectedType) {
        if (token == null || token.isBlank()) {
            throw new ApiException(ErrorCode.MALFORMED_TOKEN, "令牌为空");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new ApiException(ErrorCode.MALFORMED_TOKEN, "令牌必须为 header.payload.signature 三段");
        }
        JsonNode header = parseJson(decode(parts[0]), ErrorCode.MALFORMED_TOKEN, "令牌头部无法解析");

        // alg/typ 属于令牌可识别性检查
        if (!header.hasNonNull("alg") || !ALG_NAME.equals(header.get("alg").asText())) {
            throw new ApiException(ErrorCode.UNSUPPORTED_TOKEN, "不支持的签名算法");
        }
        String typText = header.hasNonNull("typ") ? header.get("typ").asText() : null;
        TokenType actualType = TokenType.fromHeader(typText);
        if (actualType == null) {
            throw new ApiException(ErrorCode.UNSUPPORTED_TOKEN, "不支持的令牌类型: " + typText);
        }

        // 签名覆盖头部与载荷，任何篡改都会在这里被发现
        String signingInput = parts[0] + "." + parts[1];
        byte[] expected = hmac(signingInput.getBytes(StandardCharsets.UTF_8));
        byte[] provided = decode(parts[2]);
        if (!MessageDigest.isEqual(expected, provided)) {
            throw new ApiException(ErrorCode.BAD_TOKEN_SIGNATURE, "签名校验失败，令牌可能已被篡改");
        }

        JsonNode payload = parseJson(decode(parts[1]), ErrorCode.BAD_TOKEN_SIGNATURE, "令牌载荷无法解析");
        TokenPayload parsed = readPayload(payload, actualType);

        if (actualType != expectedType) {
            throw new ApiException(ErrorCode.WRONG_TOKEN_TYPE,
                    "期望 " + expectedType + " 令牌，但提供的是 " + actualType + " 令牌")
                    .with("expected", expectedType.name())
                    .with("actual", actualType.name());
        }
        long now = clock.instant().getEpochSecond();
        if (parsed.isExpired(now)) {
            throw new ApiException(ErrorCode.TOKEN_EXPIRED,
                    expectedType + " 令牌已过期")
                    .with("expiredAt", parsed.expiresAt())
                    .with("now", now);
        }
        return parsed;
    }

    private TokenPayload readPayload(JsonNode payload, TokenType type) {
        try {
            String sub = textRequired(payload, "sub");
            String jti = textRequired(payload, "jti");
            long iat = longRequired(payload, "iat");
            long exp = longRequired(payload, "exp");
            long ver = longRequired(payload, "ver");
            return new TokenPayload(sub, jti, iat, exp, ver, type);
        } catch (ApiException ex) {
            // 载荷结构问题在签名校验之后出现，说明签名虽对但内容不合规（理论上不应来自本系统）
            throw new ApiException(ErrorCode.MALFORMED_TOKEN, "令牌载荷字段不完整或类型错误: " + ex.getMessage());
        }
    }

    private static String textRequired(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            throw new ApiException(ErrorCode.MALFORMED_TOKEN, "字段缺失或非法: " + field);
        }
        return value.asText();
    }

    private static long longRequired(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.canConvertToLong()) {
            throw new ApiException(ErrorCode.MALFORMED_TOKEN, "字段缺失或非法: " + field);
        }
        return value.longValue();
    }

    private byte[] hmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(properties.getHmacSecret().getBytes(StandardCharsets.UTF_8), ALGORITHM));
            return mac.doFinal(data);
        } catch (Exception ex) {
            throw new IllegalStateException("HMAC 计算失败: " + ex.getMessage(), ex);
        }
    }

    private static byte[] decode(String part) {
        try {
            return URL_DECODER.decode(part);
        } catch (IllegalArgumentException ex) {
            throw new ApiException(ErrorCode.MALFORMED_TOKEN, "令牌 Base64URL 解码失败");
        }
    }

    private static String encode(byte[] data) {
        return URL_ENCODER.encodeToString(data);
    }

    private static byte[] toJson(Map<String, Object> value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (Exception ex) {
            throw new IllegalStateException("令牌 JSON 序列化失败", ex);
        }
    }

    private static JsonNode parseJson(byte[] data, ErrorCode errorCode, String message) {
        try {
            return MAPPER.readTree(data);
        } catch (Exception ex) {
            throw new ApiException(errorCode, message);
        }
    }

    public MutableClock clock() {
        return clock;
    }

    public AuthProperties properties() {
        return properties;
    }
}
