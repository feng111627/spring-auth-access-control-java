package com.github.feng111627.springauthaccesscontroljava.tests.token;

import com.github.feng111627.springauthaccesscontroljava.config.AuthProperties;
import com.github.feng111627.springauthaccesscontroljava.config.MutableClock;
import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import com.github.feng111627.springauthaccesscontroljava.token.TokenPayload;
import com.github.feng111627.springauthaccesscontroljava.token.TokenService;
import com.github.feng111627.springauthaccesscontroljava.token.TokenType;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务覆盖：访问/刷新令牌的签发，以及令牌异常的可区分失败原因
 * （缺失、结构非法、算法不支持、签名篡改、载荷篡改、类型错用、过期）。
 */
class TokenServiceTest {

    private MutableClock clock;
    private TokenService tokens;
    private User user;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        clock.freezeAt(Instant.parse("2026-10-03T00:00:00Z"));
        AuthProperties properties = new AuthProperties();
        properties.setAccessTokenTtl(Duration.ofSeconds(2));
        properties.setRefreshTokenTtl(Duration.ofSeconds(5));
        tokens = new TokenService(properties, clock);
        user = new User("alice", "hash", Set.of("USER"), Set.of("report:read"),
                com.github.feng111627.springauthaccesscontroljava.user.UserStatus.ACTIVE);
    }

    @Test
    @DisplayName("合法访问令牌可校验通过，载荷字段与类型正确")
    void validAccessToken() {
        String token = tokens.issue(user, TokenType.ACCESS);
        TokenPayload payload = tokens.verify(token, TokenType.ACCESS);
        assertEquals("alice", payload.subject());
        assertEquals(TokenType.ACCESS, payload.type());
        assertEquals(0, payload.version());
        assertEquals(clock.instant().getEpochSecond() + 2, payload.expiresAt());
    }

    @Test
    @DisplayName("空令牌或非三段结构 -> MALFORMED_TOKEN")
    void malformedStructure() {
        assertCode(ErrorCode.MALFORMED_TOKEN, () -> tokens.verify(null, TokenType.ACCESS));
        assertCode(ErrorCode.MALFORMED_TOKEN, () -> tokens.verify("only-one-part", TokenType.ACCESS));
        assertCode(ErrorCode.MALFORMED_TOKEN, () -> tokens.verify("a.b", TokenType.ACCESS));
        assertCode(ErrorCode.MALFORMED_TOKEN, () -> tokens.verify("a..c", TokenType.ACCESS));
        assertCode(ErrorCode.MALFORMED_TOKEN, () -> tokens.verify("@@@.@@@.@@@", TokenType.ACCESS));
    }

    @Test
    @DisplayName("头部声明未知算法 -> UNSUPPORTED_TOKEN")
    void unsupportedAlgorithm() {
        String token = tokens.issue(user, TokenType.ACCESS);
        String forged = replaceHeaderClaim(token, "alg", "\"none\"");
        assertCode(ErrorCode.UNSUPPORTED_TOKEN, () -> tokens.verify(forged, TokenType.ACCESS));
    }

    @Test
    @DisplayName("头部声明未知令牌类型 -> UNSUPPORTED_TOKEN")
    void unsupportedType() {
        String token = tokens.issue(user, TokenType.ACCESS);
        String forged = replaceHeaderClaim(token, "typ", "\"weird\"");
        assertCode(ErrorCode.UNSUPPORTED_TOKEN, () -> tokens.verify(forged, TokenType.ACCESS));
    }

    @Test
    @DisplayName("签名段被篡改 -> BAD_TOKEN_SIGNATURE，而非过期等其他错误")
    void tamperedSignature() {
        String token = tokens.issue(user, TokenType.ACCESS);
        String tampered = token + "B"; // 确定性地改变签名段
        assertCode(ErrorCode.BAD_TOKEN_SIGNATURE, () -> tokens.verify(tampered, TokenType.ACCESS));
    }

    @Test
    @DisplayName("载荷被篡改（改用户名）但保留原签名 -> BAD_TOKEN_SIGNATURE")
    void tamperedPayload() {
        String token = tokens.issue(user, TokenType.ACCESS);
        String[] parts = token.split("\\.", -1);
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String changed = payloadJson.replace("alice", "admin");
        parts[1] = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(changed.getBytes(StandardCharsets.UTF_8));
        String tampered = parts[0] + "." + parts[1] + "." + parts[2];
        assertCode(ErrorCode.BAD_TOKEN_SIGNATURE, () -> tokens.verify(tampered, TokenType.ACCESS));
    }

    @Test
    @DisplayName("用另一把密钥签发的令牌 -> BAD_TOKEN_SIGNATURE")
    void foreignSecret() {
        AuthProperties other = new AuthProperties();
        other.setHmacSecret("a-totally-different-secret-9999");
        TokenService foreignTokens = new TokenService(other, clock);
        String foreign = foreignTokens.issue(user, TokenType.ACCESS);
        assertCode(ErrorCode.BAD_TOKEN_SIGNATURE, () -> tokens.verify(foreign, TokenType.ACCESS));
    }

    @Test
    @DisplayName("拿刷新令牌访问受保护接口 -> WRONG_TOKEN_TYPE（而非过期/签名错误）")
    void refreshTokenUsedAsAccess() {
        String refresh = tokens.issue(user, TokenType.REFRESH);
        ApiException ex = assertCode(ErrorCode.WRONG_TOKEN_TYPE,
                () -> tokens.verify(refresh, TokenType.ACCESS));
        assertEquals("REFRESH", ex.details().get("actual"));
        assertEquals("ACCESS", ex.details().get("expected"));
    }

    @Test
    @DisplayName("拿访问令牌去刷新 -> WRONG_TOKEN_TYPE")
    void accessTokenUsedAsRefresh() {
        String access = tokens.issue(user, TokenType.ACCESS);
        assertCode(ErrorCode.WRONG_TOKEN_TYPE, () -> tokens.verify(access, TokenType.REFRESH));
    }

    @Test
    @DisplayName("访问令牌超过 TTL -> TOKEN_EXPIRED，且 details 带过期时刻")
    void accessTokenExpires() {
        String access = tokens.issue(user, TokenType.ACCESS);
        clock.advance(Duration.ofSeconds(2));
        ApiException ex = assertCode(ErrorCode.TOKEN_EXPIRED,
                () -> tokens.verify(access, TokenType.ACCESS));
        assertTrue(ex.details().containsKey("expiredAt"));
    }

    @Test
    @DisplayName("刷新令牌超过刷新 TTL -> TOKEN_EXPIRED")
    void refreshTokenExpires() {
        String refresh = tokens.issue(user, TokenType.REFRESH);
        clock.advance(Duration.ofSeconds(5));
        assertCode(ErrorCode.TOKEN_EXPIRED, () -> tokens.verify(refresh, TokenType.REFRESH));
    }

    @Test
    @DisplayName("同时过期且类型错误时，类型错误优先于过期（结果确定）")
    void wrongTypeCheckedBeforeExpiry() {
        String access = tokens.issue(user, TokenType.ACCESS);
        clock.advance(Duration.ofMinutes(10));
        assertCode(ErrorCode.WRONG_TOKEN_TYPE, () -> tokens.verify(access, TokenType.REFRESH));
    }

    private String replaceHeaderClaim(String token, String claim, String jsonValue) {
        String[] parts = token.split("\\.", -1);
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        String replaced = headerJson.replaceAll("\"" + claim + "\"\\s*:\\s*\"[^\"]*\"",
                "\"" + claim + "\":" + jsonValue);
        parts[0] = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(replaced.getBytes(StandardCharsets.UTF_8));
        return parts[0] + "." + parts[1] + "." + parts[2];
    }

    private ApiException assertCode(ErrorCode expected, Runnable action) {
        ApiException ex = assertThrows(ApiException.class, action::run);
        assertEquals(expected, ex.code(),
                "期望错误码 " + expected + " 但实际为 " + ex.code());
        return ex;
    }
}
