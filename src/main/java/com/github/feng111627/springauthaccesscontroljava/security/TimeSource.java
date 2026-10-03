package com.github.feng111627.springauthaccesscontroljava.security;

/** Time abstraction so token expiry and lock windows can be controlled in tests. */
public interface TimeSource {
    long nowMillis();
}
