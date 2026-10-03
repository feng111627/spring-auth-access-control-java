package com.github.feng111627.springauthaccesscontroljava.security;

/**
 * Machine-readable, distinguishable reasons a token may be rejected.
 * Callers never collapse these into a single generic failure.
 */
public enum TokenError {
    MALFORMED,        // not a well-formed token envelope
    SIGNATURE_INVALID,// envelope parsed but HMAC does not match (tampered)
    EXPIRED,          // signature valid but past expiry
    WRONG_TYPE,       // e.g. refresh token presented to a protected API
    REVOKED,          // token was explicitly revoked (logout)
    STALE_EPOCH,      // permissions/state changed; older tokens carry a stale epoch
    USER_DISABLED     // token valid, but the account is currently disabled
}
