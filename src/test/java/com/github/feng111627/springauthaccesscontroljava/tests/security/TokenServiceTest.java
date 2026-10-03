package com.github.feng111627.springauthaccesscontroljava.tests.security;

import com.github.feng111627.springauthaccesscontroljava.security.TimeSource;
import com.github.feng111627.springauthaccesscontroljava.security.TokenError;
import com.github.feng111627.springauthaccesscontroljava.security.TokenException;
import com.github.feng111627.springauthaccesscontroljava.security.TokenPair;
import com.github.feng111627.springauthaccesscontroljava.security.TokenPayload;
import com.github.feng111627.springauthaccesscontroljava.security.TokenService;
import com.github.feng111627.springauthaccesscontroljava.security.TokenType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Covers token lifecycle edge cases: well-formed acceptance, payload/signature
 * tampering, malformed envelopes, expiry and token-type confusion. Every
 * rejection must surface a distinct {@link TokenError}.
 */
class TokenServiceTest {

    private static final String SECRET =
            "unit-test-secret-key-that-is-at-least-32-bytes-long-0001";
    private static final long ACCESS_TTL = 60_000;
    private static final long REFRESH_TTL = 600_000;

    private final AtomicLong clock = new AtomicLong(1_000_000L);
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        TimeSource timeSource = clock::get;
        tokenService = new TokenService(
                SECRET, ACCESS_TTL, REFRESH_TTL, timeSource);
    }

    private TokenPair login() {
        return tokenService.issue("alice", 1L);
    }

    private TokenException expectRejected(String token, TokenType expected) {
        return assertThrows(TokenException.class,
                () -> tokenService.verify(token, expected));
    }

    @Nested
    @DisplayName("令牌正常生命周期")
    class HappyPath {

        @Test
        @DisplayName("合法 access token 校验通过并携带主题/类型/epoch")
        void validAccessTokenVerifies() {
            TokenPair pair = login();
            TokenPayload payload = assertDoesNotThrow(
                    () -> tokenService.verify(pair.accessToken(), TokenType.ACCESS));
            assertEquals("alice", payload.subject());
            assertEquals(TokenType.ACCESS, payload.type());
            assertEquals(1L, payload.epoch());
            assertEquals(clock.get() + ACCESS_TTL, payload.expiresAt());
        }

        @Test
        @DisplayName("合法 refresh token 校验通过")
        void validRefreshTokenVerifies() {
            TokenPayload payload = tokenService.verify(
                    login().refreshToken(), TokenType.REFRESH);
            assertEquals(TokenType.REFRESH, payload.type());
            assertEquals("alice", payload.subject());
        }

        @Test
        @DisplayName("同一时刻连续签发的 token jti 彼此不同")
        void issuedTokensHaveUniqueJti() {
            TokenPair first = login();
            TokenPair second = login();
            assertNotEquals(first.accessToken(), second.accessToken());
            assertNotEquals(first.refreshToken(), second.refreshToken());
        }
    }

    @Nested
    @DisplayName("令牌被篡改必须可区分地拒绝")
    class Tampering {

        @Test
        @DisplayName("修改 payload 段(主体) -> SIGNATURE_INVALID")
        void tamperedPayloadIsSignatureInvalid() {
            TokenPair pair = login();
            String[] parts = pair.accessToken().split("\\.");
            String forgedBody = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"sub\":\"bob\"}".getBytes(StandardCharsets.UTF_8));
            String forged = parts[0] + "." + forgedBody + "." + parts[2];

            TokenException ex = expectRejected(forged, TokenType.ACCESS);
            assertEquals(TokenError.SIGNATURE_INVALID, ex.getError());
        }

        @Test
        @DisplayName("直接改写字节翻转签名 -> SIGNATURE_INVALID")
        void flippedSignatureIsInvalid() {
            TokenPair pair = login();
            String[] parts = pair.accessToken().split("\\.");
            byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
            sig[0] ^= 0x01;
            String forgedSig = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(sig);
            String forged = parts[0] + "." + parts[1] + "." + forgedSig;

            TokenException ex = expectRejected(forged, TokenType.ACCESS);
            assertEquals(TokenError.SIGNATURE_INVALID, ex.getError());
        }

        @Test
        @DisplayName("用另一个密钥重新签名的 token -> SIGNATURE_INVALID")
        void tokenSignedWithAnotherSecretIsRejected() {
            TokenService attacker = new TokenService(
                    "another-secret-key-also-at-least-32-bytes-long-99",
                    ACCESS_TTL, REFRESH_TTL, clock::get);
            String forged = attacker.issueOne("alice", TokenType.ACCESS, 1L);

            TokenException ex = expectRejected(forged, TokenType.ACCESS);
            assertEquals(TokenError.SIGNATURE_INVALID, ex.getError());
        }

        @Test
        @DisplayName("删除分段/乱填 -> MALFORMED")
        void garbageTokensAreMalformed() {
            assertEquals(TokenError.MALFORMED,
                    expectRejected(null, TokenType.ACCESS).getError());
            assertEquals(TokenError.MALFORMED,
                    expectRejected("   ", TokenType.ACCESS).getError());
            assertEquals(TokenError.MALFORMED,
                    expectRejected("only.one", TokenType.ACCESS).getError());
            assertEquals(TokenError.MALFORMED,
                    expectRejected("a..c", TokenType.ACCESS).getError());
            assertEquals(TokenError.MALFORMED,
                    expectRejected("a.b.###notbase64###", TokenType.ACCESS)
                            .getError());
        }
    }

    @Nested
    @DisplayName("过期与类型必须可区分")
    class ExpiryAndType {

        @Test
        @DisplayName("时钟越过 access 过期点 -> EXPIRED")
        void expiredAccessTokenIsRejectedAsExpired() {
            String token = login().accessToken();
            clock.addAndGet(ACCESS_TTL); // exactly at expiry boundary
            TokenException atBoundary = expectRejected(token, TokenType.ACCESS);
            assertEquals(TokenError.EXPIRED, atBoundary.getError());

            clock.incrementAndGet();
            TokenException after = expectRejected(token, TokenType.ACCESS);
            assertEquals(TokenError.EXPIRED, after.getError());
        }

        @Test
        @DisplayName("时钟越过 refresh 过期点 -> EXPIRED")
        void expiredRefreshTokenIsRejectedAsExpired() {
            String token = login().refreshToken();
            clock.addAndGet(REFRESH_TTL + 1);
            assertEquals(TokenError.EXPIRED,
                    expectRejected(token, TokenType.REFRESH).getError());
        }

        @Test
        @DisplayName("未过期但把 refresh token 用于受保护接口 -> WRONG_TYPE")
        void refreshTokenPresentedAsAccessIsWrongType() {
            TokenPair pair = login();
            TokenException ex = expectRejected(pair.refreshToken(), TokenType.ACCESS);
            assertEquals(TokenError.WRONG_TYPE, ex.getError());
        }

        @Test
        @DisplayName("把 access token 用于刷新接口 -> WRONG_TYPE")
        void accessTokenPresentedAsRefreshIsWrongType() {
            TokenPair pair = login();
            TokenException ex = expectRejected(pair.accessToken(), TokenType.REFRESH);
            assertEquals(TokenError.WRONG_TYPE, ex.getError());
        }

        @Test
        @DisplayName("过期判定优先于类型判定, 过期 access 当 refresh 仍报 EXPIRED")
        void expiryCheckedBeforeType() {
            String token = login().accessToken();
            clock.addAndGet(ACCESS_TTL + 1);
            assertEquals(TokenError.EXPIRED,
                    expectRejected(token, TokenType.REFRESH).getError());
        }
    }
}
