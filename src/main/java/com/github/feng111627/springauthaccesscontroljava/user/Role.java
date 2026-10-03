package com.github.feng111627.springauthaccesscontroljava.user;

import java.util.Set;

/**
 * Built-in roles, each mapped to a fixed set of coarse permissions.
 * Users may additionally hold fine-grained permissions directly.
 */
public enum Role {

    ADMIN(Set.of("article:publish", "article:read", "admin:stats")),
    EDITOR(Set.of("article:publish", "article:read")),
    VIEWER(Set.of("article:read"));

    private final Set<String> permissions;

    Role(Set<String> permissions) {
        this.permissions = permissions;
    }

    public Set<String> permissions() {
        return permissions;
    }
}
