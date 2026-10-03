package com.github.feng111627.springauthaccesscontroljava.user;

import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 用户仓储（线程安全的内存实现）。
 * 用户名唯一；所有读写都经过 ConcurrentHashMap，用户对象内部字段为 volatile。
 */
@Repository
public class UserRepository {

    private final ConcurrentHashMap<String, User> store = new ConcurrentHashMap<>();

    public Optional<User> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(store.get(username));
    }

    public User getRequired(String username) {
        return findByUsername(username)
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND, "用户不存在: " + username));
    }

    public User create(String username, String passwordHash, Set<String> roles, Set<String> permissions) {
        if (username == null || username.isBlank()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "用户名不能为空");
        }
        User user = new User(username, passwordHash,
                roles == null ? Set.of() : roles,
                permissions == null ? Set.of() : permissions,
                UserStatus.ACTIVE);
        User previous = store.putIfAbsent(username, user);
        if (previous != null) {
            throw new ApiException(ErrorCode.USER_ALREADY_EXISTS, "用户名已存在: " + username);
        }
        return user;
    }

    public List<User> findAll() {
        return store.values().stream().sorted(java.util.Comparator.comparing(User::getUsername)).toList();
    }

    /**
     * 仅供测试：清空全部用户，让每个用例从确定初态开始。
     */
    public void resetForTesting() {
        store.clear();
    }
}
