package com.github.feng111627.springauthaccesscontroljava.login.dto;

/**
 * 令牌签发/刷新结果。
 *
 * @param tokenType           固定 Bearer
 * @param accessToken         访问令牌
 * @param refreshToken        刷新令牌
 * @param expiresInSeconds    访问令牌有效期（秒）
 * @param refreshExpiresInSeconds 刷新令牌有效期（秒）
 */
public record TokenResponse(String tokenType, String accessToken, String refreshToken,
                            long expiresInSeconds, long refreshExpiresInSeconds) {
}
