package com.github.feng111627.springauthaccesscontroljava.security;

import java.util.Set;

/** Identity and live authorisation data attached to a verified request. */
public record AuthenticatedUser(
        String username,
        Set<String> roles,
        Set<String> permissions,
        long epoch
) {
}
