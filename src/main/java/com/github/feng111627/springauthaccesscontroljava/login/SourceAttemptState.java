package com.github.feng111627.springauthaccesscontroljava.login;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * Per-source mutable counters aggregating credential failures across all
 * usernames presented from the same source (unknown usernames included)
 * within one sliding window.
 *
 * <p>Every method is {@code synchronized} on this instance so concurrent
 * attempts from one source can never lose increments, double-count, or
 * overwrite each other.
 *
 * <p>This dimension is intentionally independent of the per-username state
 * (account lockout and the per-username window): it never resets on a
 * successful login, because a success for one username says nothing about
 * the burst of failures against other usernames from the same source.
 */
class SourceAttemptState {

    private final int maxSourceFailures;
    private final long sourceWindowMillis;

    private final Deque<Long> failureTimes = new ArrayDeque<>();

    SourceAttemptState(int maxSourceFailures, long sourceWindowMillis) {
        this.maxSourceFailures = maxSourceFailures;
        this.sourceWindowMillis = sourceWindowMillis;
    }

    /**
     * Gate evaluated before credentials are checked.
     *
     * @return {@code null} when the attempt may proceed, otherwise
     *         {@code SOURCE_RATE_LIMITED:<retryAfterMillis>}
     */
    synchronized String checkGate(long now) {
        pruneWindow(now);
        if (failureTimes.size() >= maxSourceFailures) {
            long oldest = failureTimes.peekFirst();
            long retryAfter = sourceWindowMillis - (now - oldest);
            return LoginError.SOURCE_RATE_LIMITED.name() + ":"
                    + Math.max(0, retryAfter);
        }
        return null;
    }

    /** Record one credential failure (any username, existing or not). */
    synchronized void recordFailure(long now) {
        pruneWindow(now);
        failureTimes.addLast(now);
    }

    /** Number of failures still inside the current window. */
    synchronized int windowFailureCount(long now) {
        pruneWindow(now);
        return failureTimes.size();
    }

    synchronized List<Long> recentFailureTimesSnapshot(long now) {
        pruneWindow(now);
        return List.copyOf(failureTimes);
    }

    private void pruneWindow(long now) {
        long cutoff = now - sourceWindowMillis;
        while (!failureTimes.isEmpty() && failureTimes.peekFirst() <= cutoff) {
            failureTimes.removeFirst();
        }
    }
}
