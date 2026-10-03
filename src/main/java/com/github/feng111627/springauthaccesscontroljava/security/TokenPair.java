package com.github.feng111627.springauthaccesscontroljava.security;

/** Tokens issued on successful login or refresh. */
public record TokenPair(
        String accessToken,
        String refreshToken,
        long accessTokenExpiresInMillis,
        long refreshTokenExpiresInMillis
) {
}
