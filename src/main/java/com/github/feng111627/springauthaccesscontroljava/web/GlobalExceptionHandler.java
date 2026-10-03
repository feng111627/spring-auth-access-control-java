package com.github.feng111627.springauthaccesscontroljava.web;

import com.github.feng111627.springauthaccesscontroljava.login.LoginError;
import com.github.feng111627.springauthaccesscontroljava.login.LoginException;
import com.github.feng111627.springauthaccesscontroljava.security.AccessDeniedException;
import com.github.feng111627.springauthaccesscontroljava.security.TokenError;
import com.github.feng111627.springauthaccesscontroljava.security.TokenException;
import com.github.feng111627.springauthaccesscontroljava.web.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

/**
 * Maps each distinguishable failure to a stable HTTP status and machine
 * readable error code. Unauthenticated failures never share a status with an
 * authenticated-but-forbidden one.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(TokenException.class)
    public ResponseEntity<ErrorResponse> handleToken(TokenException ex) {
        TokenError error = ex.getError();
        HttpStatus status;
        String message;
        switch (error) {
            case SIGNATURE_INVALID -> {
                status = HttpStatus.UNAUTHORIZED;
                message = "Token signature is invalid (the token was tampered with)";
            }
            case EXPIRED -> {
                status = HttpStatus.UNAUTHORIZED;
                message = "Token has expired";
            }
            case WRONG_TYPE -> {
                status = HttpStatus.UNAUTHORIZED;
                message = "Token type is not accepted for this operation";
            }
            case REVOKED -> {
                status = HttpStatus.UNAUTHORIZED;
                message = "Token has been revoked";
            }
            case STALE_EPOCH -> {
                status = HttpStatus.UNAUTHORIZED;
                message = "Token predates the latest account change; please log in again";
            }
            case USER_DISABLED -> {
                status = HttpStatus.UNAUTHORIZED;
                message = "Account is disabled";
            }
            case MALFORMED -> {
                status = HttpStatus.UNAUTHORIZED;
                message = "Missing or malformed token";
            }
            default -> {
                status = HttpStatus.UNAUTHORIZED;
                message = "Token is not accepted";
            }
        }
        return respond(status, "TOKEN_" + error.name(), message);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        // Authenticated identity, insufficient authority: 403, not 401.
        return respond(HttpStatus.FORBIDDEN, "ACCESS_DENIED", ex.getMessage());
    }

    @ExceptionHandler(LoginException.class)
    public ResponseEntity<ErrorResponse> handleLogin(LoginException ex) {
        LoginError error = ex.getError();
        HttpStatus status = switch (error) {
            // Credentials rejected: 401.
            case BAD_CREDENTIALS, ACCOUNT_DISABLED -> HttpStatus.UNAUTHORIZED;
            // Account lockout: 423 Locked (distinct from transient throttling).
            case ACCOUNT_LOCKED -> HttpStatus.LOCKED;
            // Sliding-window throttle: 429 Too Many Requests.
            case RATE_LIMITED -> HttpStatus.TOO_MANY_REQUESTS;
        };
        return respond(status, "LOGIN_" + error.name(), ex.getMessage());
    }

    @ExceptionHandler({IllegalArgumentException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<ErrorResponse> handleBadRequest(Exception ex) {
        return respond(HttpStatus.BAD_REQUEST, "BAD_REQUEST",
                ex.getMessage() == null ? "Malformed request" : ex.getMessage());
    }

    private ResponseEntity<ErrorResponse> respond(HttpStatus status,
                                                  String code,
                                                  String message) {
        log.debug("Responding {} {} - {}", status.value(), code, message);
        return ResponseEntity.status(status)
                .body(new ErrorResponse(code, message, Instant.now()));
    }
}
