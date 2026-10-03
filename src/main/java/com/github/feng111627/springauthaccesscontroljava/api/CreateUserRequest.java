package com.github.feng111627.springauthaccesscontroljava.api;

import java.util.Set;

public record CreateUserRequest(String username, String password, Set<String> roles,
                                Set<String> permissions, Boolean enabled) {
}
