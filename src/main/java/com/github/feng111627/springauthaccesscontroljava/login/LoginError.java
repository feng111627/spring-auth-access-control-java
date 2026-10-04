package com.github.feng111627.springauthaccesscontroljava.login;

/** Distinguishable login failure reasons. */
public enum LoginError {
    BAD_CREDENTIALS,      // unknown user or wrong password
    ACCOUNT_LOCKED,       // too many consecutive failures for this account
    RATE_LIMITED,         // too many attempts in the sliding window for this username
    SOURCE_RATE_LIMITED,  // too many failures in the sliding window for this client source
    ACCOUNT_DISABLED      // valid credentials, but the account is disabled
}
