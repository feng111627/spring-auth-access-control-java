package com.github.feng111627.springauthaccesscontroljava.login;

/** Thrown when login cannot succeed; carries a distinguishable {@link LoginError}. */
public class LoginException extends RuntimeException {
    private final LoginError error;

    public LoginException(LoginError error) {
        super(error.name());
        this.error = error;
    }

    public LoginException(LoginError error, String message) {
        super(message);
        this.error = error;
    }

    public LoginError getError() {
        return error;
    }
}
