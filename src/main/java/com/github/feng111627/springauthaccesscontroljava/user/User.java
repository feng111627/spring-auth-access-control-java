package com.github.feng111627.springauthaccesscontroljava.user;

import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 用户实体（内存存储）。
 * <p>
 * 令牌里不携带角色/权限，每次请求都实时读取本对象：因此权限与账号状态的
 * 变更对已签发令牌“即时生效”。tokenVersion 递增后，旧版本令牌立即作废，
 * 语义为“显式吊销（登出/管理员强制下线）”。
 */
public class User {

    private final String username;
    private volatile String passwordHash;
    private volatile Set<String> roles;
    private volatile Set<String> permissions;
    private volatile UserStatus status;
    private final AtomicLong tokenVersion = new AtomicLong(0);

    public User(String username, String passwordHash, Set<String> roles,
                Set<String> permissions, UserStatus status) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.roles = Set.copyOf(roles);
        this.permissions = Set.copyOf(permissions);
        this.status = status;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = Set.copyOf(roles);
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<String> permissions) {
        this.permissions = Set.copyOf(permissions);
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public long getTokenVersion() {
        return tokenVersion.get();
    }

    public long bumpTokenVersion() {
        return tokenVersion.incrementAndGet();
    }
}
