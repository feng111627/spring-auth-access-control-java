package com.github.feng111627.springauthaccesscontroljava.token;

/**
 * 令牌解包后的载荷。
 *
 * @param subject   用户名
 * @param tokenId   令牌唯一标识（jti）
 * @param issuedAt  签发时间（epoch 秒）
 * @param expiresAt 过期时间（epoch 秒）
 * @param version   签发时的用户令牌版本（用于即时吊销/状态变更）
 * @param type      令牌类型
 */
public record TokenPayload(
        String subject,
        String tokenId,
        long issuedAt,
        long expiresAt,
        long version,
        TokenType type) {

    public boolean isExpired(long nowEpochSeconds) {
        return nowEpochSeconds >= expiresAt;
    }
}
