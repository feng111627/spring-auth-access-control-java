package com.github.feng111627.springauthaccesscontroljava.login;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Per-source mutable failure window. All methods are synchronized on this
 * instance so concurrent attempts from the same source can never lose
 * increments or overwrite one another's records.
 *
 * <p>Unlike the per-username state there is no lockout here: the source
 * dimension is a pure sliding-window throttle over <em>all</em> credential
 * failures originating from one client source, regardless of which username
 * (existing or not) each attempt targeted.
 */
class SourceAttemptState {

    private final int maxWindowFailures;
    private final long windowMillis;

    private final Deque<Long> failureTimes = new ArrayDeque<>();

    SourceAttemptState(int maxWindowFailures, long windowMillis) {
        this.maxWindowFailures = maxWindowFailures;
        this.windowMillis = windowMillis;
    }

    /**
     * Gate evaluated before credentials are checked.
     *
     * @return {@code null} when the attempt may proceed, otherwise the
     *         suggested retry-after delay in milliseconds (as a string)
     */
    synchronized String checkGate(long now) {
        pruneWindow(now);
        if (failureTimes.size() >= maxWindowFailures) {
            long oldest = failureTimes.peekFirst();
            long retryAfter = windowMillis - (now - oldest);
            return String.valueOf(Math.max(0, retryAfter));
        }
        return null;
    }

    /**
     * Atomically apply a failed credential check. Gate-blocked attempts are
     * never recorded (the login flow records only after passing the gate), so
     * throttled traffic cannot extend its own window.
     */
    synchronized void recordFailure(long now) {
        pruneWindow(now);
        failureTimes.addLast(now);
    }

    synchronized int recentFailureCount(long now) {
        pruneWindow(now);
        return failureTimes.size();
    }

    private void pruneWindow(long now) {
        long cutoff = now - windowMillis;
        while (!failureTimes.isEmpty() && failureTimes.peekFirst() <= cutoff) {
            failureTimes.removeFirst();
        }
    }
}
