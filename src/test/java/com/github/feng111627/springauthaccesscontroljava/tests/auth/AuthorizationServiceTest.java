package com.github.feng111627.springauthaccesscontroljava.tests.auth;

import com.github.feng111627.springauthaccesscontroljava.auth.AuthorizationService;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务覆盖：角色判定、权限判定、多值 OR 语义，以及权限集合变更后“实时生效”。
 */
class AuthorizationServiceTest {

    private final AuthorizationService authorization = new AuthorizationService();

    private User user(Set<String> roles, Set<String> permissions) {
        return new User("bob", "hash", roles, permissions, UserStatus.ACTIVE);
    }

    @Test
    @DisplayName("拥有指定角色 -> 判定通过")
    void roleMatch() {
        User bob = user(Set.of("USER"), Set.of());
        assertTrue(authorization.hasAnyRole(bob, "USER"));
    }

    @Test
    @DisplayName("缺少指定角色 -> 判定不通过")
    void roleMismatch() {
        User bob = user(Set.of("USER"), Set.of());
        assertFalse(authorization.hasAnyRole(bob, "ADMIN"));
    }

    @Test
    @DisplayName("多角色为 OR 语义，满足其一即可")
    void roleAnyOf() {
        User bob = user(Set.of("USER"), Set.of());
        assertTrue(authorization.hasAnyRole(bob, "ADMIN", "USER"));
        assertFalse(authorization.hasAnyRole(bob, "ADMIN", "AUDITOR"));
    }

    @Test
    @DisplayName("权限判定与角色相互独立：有角色不等于有权限")
    void permissionIndependentFromRole() {
        User bob = user(Set.of("USER"), Set.of());
        assertFalse(authorization.hasAnyPermission(bob, "report:read"));
        User alice = user(Set.of("USER"), Set.of("report:read"));
        assertTrue(authorization.hasAnyPermission(alice, "report:read"));
    }

    @Test
    @DisplayName("多权限为 OR 语义")
    void permissionAnyOf() {
        User alice = user(Set.of("USER"), Set.of("report:read"));
        assertTrue(authorization.hasAnyPermission(alice, "user:admin", "report:read"));
    }

    @Test
    @DisplayName("权限被管理员移除后立即按新集合判定（无需重新签发令牌）")
    void permissionChangeTakesEffectImmediately() {
        User alice = user(Set.of("USER"), Set.of("report:read"));
        assertTrue(authorization.hasAnyPermission(alice, "report:read"));

        alice.setPermissions(Set.of());
        assertFalse(authorization.hasAnyPermission(alice, "report:read"));
    }

    @Test
    @DisplayName("新增角色后立即生效")
    void roleGrantTakesEffectImmediately() {
        User bob = user(Set.of("USER"), Set.of());
        assertFalse(authorization.hasAnyRole(bob, "ADMIN"));
        bob.setRoles(Set.of("USER", "ADMIN"));
        assertTrue(authorization.hasAnyRole(bob, "ADMIN"));
    }
}
