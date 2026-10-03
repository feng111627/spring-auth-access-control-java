package com.github.feng111627.springauthaccesscontroljava.api;

import com.github.feng111627.springauthaccesscontroljava.auth.AuthContext;
import com.github.feng111627.springauthaccesscontroljava.login.LoginService;
import com.github.feng111627.springauthaccesscontroljava.login.dto.LoginRequest;
import com.github.feng111627.springauthaccesscontroljava.login.dto.RefreshRequest;
import com.github.feng111627.springauthaccesscontroljava.login.dto.TokenResponse;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 认证接口：登录 / 刷新（公开）、登出（需认证）。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final LoginService loginService;

    public AuthController(LoginService loginService) {
        this.loginService = loginService;
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request, HttpServletRequest http) {
        return loginService.login(request, clientIp(http));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        return loginService.refresh(request == null ? null : request.refreshToken());
    }

    @PostMapping("/logout")
    public Map<String, Object> logout() {
        User user = AuthContext.get();
        loginService.logout(user.getUsername());
        return Map.of("status", "ok", "message", "已登出，该账号所有已签发令牌立即失效");
    }

    static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
