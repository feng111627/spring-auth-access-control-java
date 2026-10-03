package com.github.feng111627.springauthaccesscontroljava.login;

import com.github.feng111627.springauthaccesscontroljava.auth.Pbkdf2PasswordEncoder;
import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import com.github.feng111627.springauthaccesscontroljava.login.dto.LoginRequest;
import com.github.feng111627.springauthaccesscontroljava.login.dto.TokenResponse;
import com.github.feng111627.springauthaccesscontroljava.token.TokenPayload;
import com.github.feng111627.springauthaccesscontroljava.token.TokenService;
import com.github.feng111627.springauthaccesscontroljava.token.TokenType;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import com.github.feng111627.springauthaccesscontroljava.user.UserStatus;
import org.springframework.stereotype.Service;

/**
 * 登录、刷新、登出编排。
 * <p>
 * 登录流程顺序固定，失败原因可区分：
 * <ol>
 *   <li>参数缺失 → INVALID_REQUEST</li>
 *   <li>IP 限流 → RATE_LIMITED；账号锁定 → ACCOUNT_LOCKED（在验密之前拦截）</li>
 *   <li>用户不存在或密码错误 → BAD_CREDENTIALS（两者不区分，避免账号枚举）</li>
 *   <li>账号停用 → ACCOUNT_DISABLED</li>
 * </ol>
 * 注意：第 5 次失败本身仍返回 BAD_CREDENTIALS，锁定从下一次尝试起生效，
 * 因此“凭据错误 / 锁定 / 限流”三种响应在测试与日志中可以明确分辨。
 */
@Service
public class LoginService {

    private final UserRepository users;
    private final Pbkdf2PasswordEncoder passwordEncoder;
    private final LoginAttemptService attempts;
    private final TokenService tokens;

    public LoginService(UserRepository users, Pbkdf2PasswordEncoder passwordEncoder,
                        LoginAttemptService attempts, TokenService tokens) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.attempts = attempts;
        this.tokens = tokens;
    }

    public TokenResponse login(LoginRequest request, String clientIp) {
        if (request == null || request.username() == null || request.username().isBlank()
                || request.password() == null || request.password().isEmpty()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "用户名和密码不能为空");
        }
        String username = request.username();

        // 先做防护闸门：限流/锁定状态优先于凭据错误暴露
        attempts.assertLoginAllowed(username, clientIp);

        User user = users.findByUsername(username).orElse(null);
        boolean passwordOk = user != null
                && passwordEncoder.matches(request.password(), user.getPasswordHash());
        if (!passwordOk) {
            // 原子地完成账号锁定复查与失败计数，杜绝并发下计数超记
            attempts.registerCredentialFailure(username, clientIp);
            throw new ApiException(ErrorCode.BAD_CREDENTIALS, "用户名或密码错误");
        }
        if (user.getStatus() == UserStatus.DISABLED) {
            // 密码正确但账号停用：不计入失败计数
            throw new ApiException(ErrorCode.ACCOUNT_DISABLED, "账号已被停用，请联系管理员");
        }

        attempts.recordSuccess(username);
        return issuePair(user);
    }

    /**
     * 用刷新令牌换取新令牌对（刷新令牌轮换：旧刷新令牌的 ver 在下一次使用时不再匹配）。
     * 刷新成功会递增令牌版本，因此旧访问令牌与旧刷新令牌同时失效。
     */
    public TokenResponse refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "refreshToken 不能为空");
        }
        // 类型用错（拿访问令牌来刷新）会得到 WRONG_TOKEN_TYPE，过期/篡改同理可区分
        TokenPayload payload = tokens.verify(refreshToken, TokenType.REFRESH);
        User user = users.findByUsername(payload.subject()).orElse(null);
        if (user == null) {
            throw new ApiException(ErrorCode.TOKEN_REVOKED, "用户不存在，令牌已失效");
        }
        if (user.getStatus() == UserStatus.DISABLED) {
            throw new ApiException(ErrorCode.ACCOUNT_DISABLED, "账号已被停用");
        }
        if (payload.version() != user.getTokenVersion()) {
            throw new ApiException(ErrorCode.TOKEN_REVOKED,
                    "刷新令牌已被轮换或吊销（版本不匹配）")
                    .with("tokenVersion", payload.version())
                    .with("currentVersion", user.getTokenVersion());
        }
        // 轮换：版本递增，旧令牌对全部作废
        user.bumpTokenVersion();
        return issuePair(user);
    }

    /** 登出：递增令牌版本，该用户所有已签发令牌立即失效（TOKEN_REVOKED）。 */
    public void logout(String username) {
        User user = users.getRequired(username);
        user.bumpTokenVersion();
    }

    private TokenResponse issuePair(User user) {
        String access = tokens.issue(user, TokenType.ACCESS);
        String refresh = tokens.issue(user, TokenType.REFRESH);
        return new TokenResponse(
                "Bearer",
                access,
                refresh,
                tokens.properties().getAccessTokenTtl().getSeconds(),
                tokens.properties().getRefreshTokenTtl().getSeconds());
    }
}
