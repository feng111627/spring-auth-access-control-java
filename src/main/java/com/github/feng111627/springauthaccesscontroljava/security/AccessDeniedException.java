package com.github.feng111627.springauthaccesscontroljava.security;

/**
 * The caller is authenticated but lacks the required role/permission.
 * Mapped to HTTP 403 (distinct from unauthenticated 401).
 */
public class AccessDeniedException extends RuntimeException {

    private final String requirement;

    public AccessDeniedException(String requirement) {
        super("Access denied: requires " + requirement);
        this.requirement = requirement;
    }

    public String getRequirement() {
        return requirement;
    }
}
