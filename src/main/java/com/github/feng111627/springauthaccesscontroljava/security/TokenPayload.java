package com.github.feng111627.springauthaccesscontroljava.security;

/** Verified contents of a token. */
public record TokenPayload(
        String subject,
        TokenType type,
        long issuedAt,
        long expiresAt,
        long epoch,
        String jti
) {
}
