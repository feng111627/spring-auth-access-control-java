package com.github.feng111627.springauthaccesscontroljava.login;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * Per-username mutable counters. Every method is {@code synchronized} on this
 * instance so that concurrent login attempts can never lose increments, reset
 * each other's counters, or double-apply a lock.
 *
 * <p>Two independent mechanisms are tracked:
 * <ul>
 *   <li><b>Account lockout</b> — {@code maxFailures} consecutive failures lock
 *       the username until {@code lockUntil};</li>
 *   <li><b>Sliding-window rate limit</b> — more than
 *       {@code maxWindowAttempts} attempts within {@code windowMillis} are
 *       rejected even between lock expiry cycles.</li>
 * </ul>
 */
class LoginAttemptState {

    private final int maxFailures;
    private final long lockMillis;
    private final int maxWindowAttempts;
    private final long windowMillis;

    private int consecutiveFailures;
    private long lockUntil;
    private final Deque<Long> failureTimes = new ArrayDeque<>();

    LoginAttemptState(int maxFailures, long lockMillis,
                      int maxWindowAttempts, long windowMillis) {
        this.maxFailures = maxFailures;
        this.lockMillis = lockMillis;
        this.maxWindowAttempts = maxWindowAttempts;
        this.windowMillis = windowMillis;
    }

    /**
     * Gate evaluated before credentials are checked.
     *
     * @return {@code null} when the attempt may proceed, otherwise a
     *         {@link LoginError} name: {@code RATE_LIMITED} takes priority
     *         (the caller is hammering the endpoint), then {@code ACCOUNT_LOCKED}
     */
    synchronized String checkGate(long now) {
        pruneWindow(now);

        // The sliding window counts all recorded failures, including failures
        // that pre-date an in-progress lockout.
        if (failureTimes.size() >= maxWindowAttempts) {
            long oldest = failureTimes.peekFirst();
            long retryAfter = windowMillis - (now - oldest);
            return LoginError.RATE_LIMITED.name() + ":" + Math.max(0, retryAfter);
        }

        if (consecutiveFailures >= maxFailures && now < lockUntil) {
            return LoginError.ACCOUNT_LOCKED.name() + ":" + (lockUntil - now);
        }
        // An expired lockout is left in place until the next failure resets
        // the counter below; recordFailure handles the roll-over.
        return null;
    }

    /**
     * Atomically apply a failed credential check. Honors an active lockout
     * without further incrementing (so concurrent losers after the
     * lock-triggering attempt cannot push counters around).
     */
    synchronized void recordFailure(long now) {
        pruneWindow(now);

        if (consecutiveFailures >= maxFailures) {
            if (now < lockUntil) {
                // Still locked: the credential check should have been blocked
                // by checkGate; keep the window untouched in that case.
                return;
            }
            // Lock just expired: start a fresh consecutive-failure cycle.
            // The sliding window is intentionally kept so the independent
            // rate limit still sees the recent burst.
            consecutiveFailures = 0;
        }

        consecutiveFailures++;
        failureTimes.addLast(now);
        if (consecutiveFailures >= maxFailures) {
            lockUntil = now + lockMillis;
        }
    }

    synchronized void recordSuccess() {
        consecutiveFailures = 0;
        lockUntil = 0;
        failureTimes.clear();
    }

    synchronized int consecutiveFailures(long now) {
        pruneWindow(now);
        if (consecutiveFailures >= maxFailures && now >= lockUntil) {
            return 0;
        }
        return consecutiveFailures;
    }

    synchronized List<Long> recentFailureTimesSnapshot(long now) {
        pruneWindow(now);
        return List.copyOf(failureTimes);
    }

    private void pruneWindow(long now) {
        long cutoff = now - windowMillis;
        while (!failureTimes.isEmpty() && failureTimes.peekFirst() <= cutoff) {
            failureTimes.removeFirst();
        }
    }
}
