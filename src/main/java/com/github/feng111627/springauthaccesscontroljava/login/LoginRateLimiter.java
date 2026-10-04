package com.github.feng111627.springauthaccesscontroljava.login;

import com.github.feng111627.springauthaccesscontroljava.security.TimeSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Two independent, individually reachable and distinguishable protection
 * dimensions for the login endpoint:
 *
 * <ol>
 *   <li><b>Account dimension (per username)</b> — consecutive-failure lockout
 *       plus a per-username sliding window (see {@link LoginAttemptState});</li>
 *   <li><b>Source dimension (per source, e.g. client IP)</b> — aggregates
 *       failures across <em>all</em> usernames presented from one source
 *       within its own sliding window (see {@link SourceAttemptState});
 *       attempts against non-existent usernames are counted just the same,
 *       so username-spraying/brute forcing is caught even when no single
 *       account reaches its own threshold.</li>
 * </ol>
 *
 * <p><b>Fixed priority when several gates trip at once:</b>
 * source rate limit ({@link LoginError#SOURCE_RATE_LIMITED}) &rarr; per-username
 * rate limit ({@link LoginError#RATE_LIMITED}) &rarr; account lockout
 * ({@link LoginError#ACCOUNT_LOCKED}). The order is constant regardless of
 * configured thresholds, windows or lock durations, so a request can never
 * produce two contradictory verdicts.
 *
 * <p><b>Concurrency.</b> Each dimension has per-key mutable state whose
 * methods are synchronized on the state instance. The login flow additionally
 * serializes a whole decision (both gate checks + credential verification +
 * outcome recording) by acquiring the source flow lock first and the username
 * flow lock second; this fixed order cannot deadlock (every caller acquires
 * the same two locks in the same order) and keeps check-then-act atomic.
 * Different source/username pairs still run in parallel.
 */
@Component
public class LoginRateLimiter {

    /** Sentinel source for callers that do not supply one (backward compat). */
    public static final String UNKNOWN_SOURCE = "unknown";

    private final TimeSource timeSource;
    private final int maxFailures;
    private final long lockMillis;
    private final int maxWindowAttempts;
    private final long windowMillis;
    private final int maxSourceFailures;
    private final long sourceWindowMillis;

    private final ConcurrentHashMap<String, LoginAttemptState> states =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SourceAttemptState> sourceStates =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> flowLocks =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> sourceFlowLocks =
            new ConcurrentHashMap<>();

    @Autowired
    public LoginRateLimiter(
            TimeSource timeSource,
            @Value("${app.login.max-failures}") int maxFailures,
            @Value("${app.login.lock-millis}") long lockMillis,
            @Value("${app.login.max-attempts-per-window}") int maxWindowAttempts,
            @Value("${app.login.window-millis}") long windowMillis,
            @Value("${app.login.max-source-failures}") int maxSourceFailures,
            @Value("${app.login.source-window-millis}") long sourceWindowMillis) {
        this.timeSource = timeSource;
        this.maxFailures = maxFailures;
        this.lockMillis = lockMillis;
        this.maxWindowAttempts = maxWindowAttempts;
        this.windowMillis = windowMillis;
        this.maxSourceFailures = maxSourceFailures;
        this.sourceWindowMillis = sourceWindowMillis;
    }

    /**
     * Convenience constructor with the source dimension disabled. Used by
     * account-dimension-only callers/tests; the shared unknown-source bucket
     * effectively never trips.
     */
    public LoginRateLimiter(
            TimeSource timeSource,
            int maxFailures,
            long lockMillis,
            int maxWindowAttempts,
            long windowMillis) {
        this(timeSource, maxFailures, lockMillis, maxWindowAttempts, windowMillis,
                Integer.MAX_VALUE, Long.MAX_VALUE);
    }

    private LoginAttemptState stateFor(String username) {
        return states.computeIfAbsent(username,
                key -> new LoginAttemptState(maxFailures, lockMillis,
                        maxWindowAttempts, windowMillis));
    }

    private SourceAttemptState sourceStateFor(String source) {
        return sourceStates.computeIfAbsent(source,
                key -> new SourceAttemptState(maxSourceFailures, sourceWindowMillis));
    }

    /** Per-username lock of a whole login decision (acquired second). */
    public Object lockFor(String username) {
        return flowLocks.computeIfAbsent(username, key -> new Object());
    }

    /** Per-source lock of a whole login decision (always acquired first). */
    public Object sourceLockFor(String source) {
        return sourceFlowLocks.computeIfAbsent(source, key -> new Object());
    }

    /**
     * Gate invoked before checking credentials, evaluating both dimensions.
     *
     * @throws LoginException SOURCE_RATE_LIMITED, RATE_LIMITED or ACCOUNT_LOCKED
     */
    public void assertAttemptAllowed(String source, String username) {
        long now = timeSource.nowMillis();

        // Dimension 1 (higher priority): aggregated failures from this source.
        String sourceGate = sourceStateFor(source).checkGate(now);
        if (sourceGate != null) {
            long retryAfterMillis = parseRetryAfter(sourceGate);
            throw new LoginException(LoginError.SOURCE_RATE_LIMITED,
                    "Too many failed login attempts from this source across "
                            + "usernames; retry after " + retryAfterMillis + " ms");
        }

        // Dimension 2: per-username window / lockout.
        String gate = stateFor(username).checkGate(now);
        if (gate == null) {
            return;
        }
        long retryAfterMillis = parseRetryAfter(gate);
        LoginError error = LoginError.valueOf(gate.split(":", 2)[0]);
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

    /** Backward-compatible gate without an explicit source. */
    public void assertAttemptAllowed(String username) {
        assertAttemptAllowed(UNKNOWN_SOURCE, username);
    }

    /** Record a credential failure against both dimensions. */
    public void recordFailure(String source, String username) {
        long now = timeSource.nowMillis();
        sourceStateFor(source).recordFailure(now);
        stateFor(username).recordFailure(now);
    }

    /** Backward-compatible failure recording (unknown source). */
    public void recordFailure(String username) {
        recordFailure(UNKNOWN_SOURCE, username);
    }

    /** A successful login clears the account counters only. */
    public void recordSuccess(String source, String username) {
        // The source window deliberately survives: one good login must not
        // erase evidence of a cross-username burst from the same source.
        stateFor(username).recordSuccess();
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

    /** Failures currently counted inside this source's sliding window. */
    public int sourceWindowFailureCount(String source) {
        return sourceStateFor(source).windowFailureCount(timeSource.nowMillis());
    }

    public List<Long> sourceRecentFailureTimes(String source) {
        return sourceStateFor(source).recentFailureTimesSnapshot(timeSource.nowMillis());
    }

    private static long parseRetryAfter(String gate) {
        String[] parts = gate.split(":", 2);
        return parts.length == 2 ? Long.parseLong(parts[1]) : 0L;
    }
}
