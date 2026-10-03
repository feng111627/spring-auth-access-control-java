package com.github.feng111627.springauthaccesscontroljava.login;

import com.github.feng111627.springauthaccesscontroljava.security.TimeSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Combines two independent, distinguishable gates per username:
 * account lockout (consecutive failures) and sliding-window rate limiting.
 *
 * <p>Each username gets its own {@link LoginAttemptState}; all decisions for a
 * username are serialized inside that state's intrinsic lock, so concurrent
 * attempts cannot lose increments or overwrite one another's lock. A separate
 * per-username lock ({@link #lockFor(String)}) is used by the login flow to
 * keep the gate-check and the outcome-recording as one atomic decision;
 * different usernames still proceed fully in parallel.
 */
@Component
public class LoginRateLimiter {

    private final TimeSource timeSource;
    private final int maxFailures;
    private final long lockMillis;
    private final int maxWindowAttempts;
    private final long windowMillis;
    private final ConcurrentHashMap<String, LoginAttemptState> states =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> flowLocks =
            new ConcurrentHashMap<>();

    public LoginRateLimiter(
            TimeSource timeSource,
            @Value("${app.login.max-failures}") int maxFailures,
            @Value("${app.login.lock-millis}") long lockMillis,
            @Value("${app.login.max-attempts-per-window}") int maxWindowAttempts,
            @Value("${app.login.window-millis}") long windowMillis) {
        this.timeSource = timeSource;
        this.maxFailures = maxFailures;
        this.lockMillis = lockMillis;
        this.maxWindowAttempts = maxWindowAttempts;
        this.windowMillis = windowMillis;
    }

    private LoginAttemptState stateFor(String username) {
        return states.computeIfAbsent(username,
                key -> new LoginAttemptState(maxFailures, lockMillis,
                        maxWindowAttempts, windowMillis));
    }

    /**
     * Per-username lock serializing a whole login decision (gate check +
     * credential verification + outcome recording). The PBKDF2 verification
     * runs inside this lock for the same username, which is intentional: the
     * failure counter must not observe a check-then-act race.
     */
    public Object lockFor(String username) {
        return flowLocks.computeIfAbsent(username, key -> new Object());
    }

    /**
     * Gate invoked before checking credentials.
     *
     * @throws LoginException RATE_LIMITED (too many attempts in the window) or
     *         ACCOUNT_LOCKED (consecutive-failure lock active)
     */
    public void assertAttemptAllowed(String username) {
        long now = timeSource.nowMillis();
        String gate = stateFor(username).checkGate(now);
        if (gate == null) {
            return;
        }
        String[] parts = gate.split(":", 2);
        long retryAfterMillis = parts.length == 2 ? Long.parseLong(parts[1]) : 0L;
        LoginError error = LoginError.valueOf(parts[0]);
        if (error == LoginError.RATE_LIMITED) {
            throw new LoginException(LoginError.RATE_LIMITED,
                    "Too many login attempts for this username; retry after "
                            + retryAfterMillis + " ms");
        }
        throw new LoginException(LoginError.ACCOUNT_LOCKED,
                "Account is temporarily locked after " + maxFailures
                        + " consecutive failed attempts; retry after "
                        + retryAfterMillis + " ms");
    }

    public void recordFailure(String username) {
        stateFor(username).recordFailure(timeSource.nowMillis());
    }

    public void recordSuccess(String username) {
        stateFor(username).recordSuccess();
    }

    public int consecutiveFailures(String username) {
        return stateFor(username).consecutiveFailures(timeSource.nowMillis());
    }

    public List<Long> recentFailureTimes(String username) {
        return stateFor(username).recentFailureTimesSnapshot(timeSource.nowMillis());
    }
}
