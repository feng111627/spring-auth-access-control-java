package com.github.feng111627.springauthaccesscontroljava.security;

/** Distinct token types; an access token and a refresh token are never interchangeable. */
public enum TokenType {
    ACCESS,
    REFRESH
}
