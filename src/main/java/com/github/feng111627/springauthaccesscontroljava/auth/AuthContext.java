package com.github.feng111627.springauthaccesscontroljava.auth;

import com.github.feng111627.springauthaccesscontroljava.user.User;

/**
 * 当前请求的认证主体（由认证拦截器写入，请求结束清理）。
 */
public class AuthContext {

    private static final ThreadLocal<User> CURRENT = new ThreadLocal<>();

    public static void set(User user) {
        CURRENT.set(user);
    }

    public static User get() {
        return CURRENT.get();
    }

    public static void clear() {
        CURRENT.remove();
    }
}
