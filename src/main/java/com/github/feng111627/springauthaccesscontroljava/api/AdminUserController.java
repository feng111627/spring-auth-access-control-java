package com.github.feng111627.springauthaccesscontroljava.api;

import com.github.feng111627.springauthaccesscontroljava.auth.Pbkdf2PasswordEncoder;
import com.github.feng111627.springauthaccesscontroljava.auth.RequirePermission;
import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import com.github.feng111627.springauthaccesscontroljava.user.UserStatus;
import com.github.feng111627.springauthaccesscontroljava.user.UserView;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 用户管理（类级要求 user:admin 权限）。权限/状态变更对已签发令牌的语义：
 * <ul>
 *   <li>改角色/权限：下一次请求实时生效（令牌不携带授权信息）；</li>
 *   <li>停用/启用：下一次请求按新状态判定（停用 → ACCOUNT_DISABLED）；</li>
 *   <li>强制下线 revoke-tokens：递增 tokenVersion，旧令牌一律 TOKEN_REVOKED。</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/admin/users")
@RequirePermission("user:admin")
public class AdminUserController {

    private final UserRepository users;
    private final Pbkdf2PasswordEncoder passwordEncoder;

    public AdminUserController(UserRepository users, Pbkdf2PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public List<UserView> list() {
        return users.findAll().stream().map(UserView::of).toList();
    }

    @PostMapping
    public UserView create(@RequestBody CreateUserRequest request) {
        if (request == null || request.username() == null || request.username().isBlank()
                || request.password() == null || request.password().isEmpty()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "用户名和密码不能为空");
        }
        String hash = passwordEncoder.encode(request.password());
        boolean enabled = request.enabled() == null || request.enabled();
        User user = users.create(request.username(), hash,
                request.roles() == null ? Set.of() : request.roles(),
                request.permissions() == null ? Set.of() : request.permissions());
        if (!enabled) {
            user.setStatus(UserStatus.DISABLED);
        }
        return UserView.of(user);
    }

    @PostMapping("/{username}/permissions")
    public UserView updatePermissions(@PathVariable String username,
                                      @RequestBody Map<String, Set<String>> body) {
        User user = users.getRequired(username);
        user.setPermissions(requireSet(body, "permissions"));
        return UserView.of(user);
    }

    @PostMapping("/{username}/roles")
    public UserView updateRoles(@PathVariable String username,
                                @RequestBody Map<String, Set<String>> body) {
        User user = users.getRequired(username);
        user.setRoles(requireSet(body, "roles"));
        return UserView.of(user);
    }

    @PostMapping("/{username}/disable")
    public UserView disable(@PathVariable String username) {
        User user = users.getRequired(username);
        user.setStatus(UserStatus.DISABLED);
        return UserView.of(user);
    }

    @PostMapping("/{username}/enable")
    public UserView enable(@PathVariable String username) {
        User user = users.getRequired(username);
        user.setStatus(UserStatus.ACTIVE);
        return UserView.of(user);
    }

    @PostMapping("/{username}/revoke-tokens")
    public Map<String, Object> revokeTokens(@PathVariable String username) {
        User user = users.getRequired(username);
        long newVersion = user.bumpTokenVersion();
        return Map.of("status", "ok", "username", username, "tokenVersion", newVersion,
                "message", "该用户所有已签发令牌已失效");
    }

    private Set<String> requireSet(Map<String, Set<String>> body, String key) {
        Set<String> values = body == null ? null : body.get(key);
        if (values == null) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "请求体必须包含 " + key + " 数组");
        }
        return values;
    }
}
