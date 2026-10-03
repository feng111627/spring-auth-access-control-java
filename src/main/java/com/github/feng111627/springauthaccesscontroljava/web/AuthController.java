package com.github.feng111627.springauthaccesscontroljava.web;

import com.github.feng111627.springauthaccesscontroljava.auth.AuthService;
import com.github.feng111627.springauthaccesscontroljava.security.TokenPair;
import com.github.feng111627.springauthaccesscontroljava.web.dto.LoginRequest;
import com.github.feng111627.springauthaccesscontroljava.web.dto.LogoutRequest;
import com.github.feng111627.springauthaccesscontroljava.web.dto.RefreshRequest;
import com.github.feng111627.springauthaccesscontroljava.web.dto.TokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        requireBody(request);
        TokenPair pair = authService.login(request.username(), request.password());
        return toResponse(pair);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        requireBody(request);
        if (request.refreshToken() == null || request.refreshToken().isBlank()) {
            throw new IllegalArgumentException("refreshToken is required");
        }
        return toResponse(authService.refresh(request.refreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequest request) {
        if (request != null) {
            authService.logout(request.refreshToken());
        }
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    private static TokenResponse toResponse(TokenPair pair) {
        return new TokenResponse(
                pair.accessToken(),
                pair.refreshToken(),
                "Bearer",
                pair.accessTokenExpiresInMillis(),
                pair.refreshTokenExpiresInMillis());
    }

    private static void requireBody(Object body) {
        if (body == null) {
            throw new IllegalArgumentException("request body is required");
        }
    }
}
