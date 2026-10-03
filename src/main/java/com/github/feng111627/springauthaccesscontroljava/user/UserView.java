package com.github.feng111627.springauthaccesscontroljava.user;

import java.util.Set;

/**
 * 用户对外视图（不含密码哈希）。
 */
public record UserView(String username, Set<String> roles, Set<String> permissions, UserStatus status) {

    public static UserView of(User user) {
        return new UserView(user.getUsername(), user.getRoles(), user.getPermissions(), user.getStatus());
    }
}
