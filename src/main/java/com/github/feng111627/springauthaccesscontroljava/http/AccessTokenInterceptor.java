package com.github.feng111627.springauthaccesscontroljava.http;

import com.github.feng111627.springauthaccesscontroljava.auth.AuthContext;
import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import com.github.feng111627.springauthaccesscontroljava.token.TokenPayload;
import com.github.feng111627.springauthaccesscontroljava.token.TokenService;
import com.github.feng111627.springauthaccesscontroljava.token.TokenType;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import com.github.feng111627.springauthaccesscontroljava.user.UserStatus;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 认证拦截器：从 Authorization: Bearer 头解析并校验访问令牌，
 * 再实时检查账号存在性、启用状态与令牌版本。
 * <p>
 * 失败与错误码：
 * MISSING_TOKEN / MALFORMED_TOKEN / UNSUPPORTED_TOKEN / BAD_TOKEN_SIGNATURE /
 * TOKEN_EXPIRED / WRONG_TOKEN_TYPE / TOKEN_REVOKED / ACCOUNT_DISABLED。
 * 令牌里没有角色权限，账号权限/状态变更在本拦截器与授权拦截器中实时生效。
 */
@Component
public class AccessTokenInterceptor implements HandlerInterceptor {

    private static final String BEARER_PREFIX = "Bearer ";

    private final TokenService tokens;
    private final UserRepository users;

    public AccessTokenInterceptor(TokenService tokens, UserRepository users) {
        this.tokens = tokens;
        this.users = users;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null || authorization.isBlank()) {
            throw new ApiException(ErrorCode.MISSING_TOKEN, "缺少 Authorization 头");
        }
        if (!authorization.startsWith(BEARER_PREFIX)) {
            throw new ApiException(ErrorCode.MALFORMED_TOKEN,
                    "Authorization 头必须以 Bearer 方案携带令牌");
        }
        String rawToken = authorization.substring(BEARER_PREFIX.length()).trim();
        if (rawToken.isEmpty()) {
            throw new ApiException(ErrorCode.MISSING_TOKEN, "Bearer 令牌为空");
        }

        // 拿刷新令牌访问接口会在这里得到 WRONG_TOKEN_TYPE
        TokenPayload payload = tokens.verify(rawToken, TokenType.ACCESS);

        User user = users.findByUsername(payload.subject()).orElse(null);
        if (user == null) {
            throw new ApiException(ErrorCode.TOKEN_REVOKED, "账号已不存在，令牌失效");
        }
        if (user.getStatus() == UserStatus.DISABLED) {
            throw new ApiException(ErrorCode.ACCOUNT_DISABLED, "账号已被停用");
        }
        if (payload.version() != user.getTokenVersion()) {
            throw new ApiException(ErrorCode.TOKEN_REVOKED,
                    "令牌版本已失效（已登出、被强制下线或已通过刷新轮换）")
                    .with("tokenVersion", payload.version())
                    .with("currentVersion", user.getTokenVersion());
        }

        AuthContext.set(user);
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        AuthContext.clear();
    }
}
