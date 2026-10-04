package com.github.feng111627.springauthaccesscontroljava.login;

import com.github.feng111627.springauthaccesscontroljava.security.TimeSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Aggregates login failures per client source (e.g. remote IP), across all
 * usernames including non-existent ones, so credential-stuffing bursts that
 * rotate usernames from one client are throttled as a whole.
 */
@Component
public class SourceRateLimiter {

    private final TimeSource timeSource;
    private final int maxWindowFailures;
    private final long windowMillis;
    private final ConcurrentHashMap<String, SourceAttemptState> states =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> flowLocks =
            new ConcurrentHashMap<>();

    public SourceRateLimiter(
            TimeSource timeSource,
            @Value("${app.login.source.max-failures-per-window}") int maxWindowFailures,
            @Value("${app.login.source.window-millis}") long windowMillis) {
        this.timeSource = timeSource;
        this.maxWindowFailures = maxWindowFailures;
        this.windowMillis = windowMillis;
    }

    private SourceAttemptState stateFor(String source) {
        return states.computeIfAbsent(source,
                key -> new SourceAttemptState(maxWindowFailures, windowMillis));
    }

    /** Per-source lock serializing a whole login decision for that source. */
    public Object lockFor(String source) {
        return flowLocks.computeIfAbsent(source, key -> new Object());
    }

    /**
     * Gate invoked before checking credentials.
     *
     * @throws LoginException SOURCE_RATE_LIMITED when the source's failure
     *         window is full
     */
    public void assertAttemptAllowed(String source) {
        String retryAfter = stateFor(source).checkGate(timeSource.nowMillis());
        if (retryAfter != null) {
            throw new LoginException(LoginError.SOURCE_RATE_LIMITED,
                    "Too many failed login attempts from this source; retry after "
                            + retryAfter + " ms");
        }
    }

    public void recordFailure(String source) {
        stateFor(source).recordFailure(timeSource.nowMillis());
    }

    public int recentFailureCount(String source) {
        return stateFor(source).recentFailureCount(timeSource.nowMillis());
    }
}
