package com.github.feng111627.springauthaccesscontroljava.web.dto;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long accessTokenExpiresInMillis,
        long refreshTokenExpiresInMillis
) {
}
