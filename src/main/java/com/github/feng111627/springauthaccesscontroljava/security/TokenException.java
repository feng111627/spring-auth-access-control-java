package com.github.feng111627.springauthaccesscontroljava.security;

/** Thrown when a token cannot be accepted; carries a distinguishable {@link TokenError}. */
public class TokenException extends RuntimeException {
    private final TokenError error;

    public TokenException(TokenError error) {
        super(error.name());
        this.error = error;
    }

    public TokenError getError() {
        return error;
    }
}
