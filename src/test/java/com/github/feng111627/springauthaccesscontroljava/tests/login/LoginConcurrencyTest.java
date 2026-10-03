package com.github.feng111627.springauthaccesscontroljava.tests.login;

import com.github.feng111627.springauthaccesscontroljava.login.LoginError;
import com.github.feng111627.springauthaccesscontroljava.login.LoginException;
import com.github.feng111627.springauthaccesscontroljava.login.LoginRateLimiter;
import com.github.feng111627.springauthaccesscontroljava.security.PasswordEncoder;
import com.github.feng111627.springauthaccesscontroljava.security.TimeSource;
import com.github.feng111627.springauthaccesscontroljava.security.TokenPair;
import com.github.feng111627.springauthaccesscontroljava.security.TokenService;
import com.github.feng111627.springauthaccesscontroljava.security.TokenRevocationService;
import com.github.feng111627.springauthaccesscontroljava.user.Role;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import com.github.feng111627.springauthaccesscontroljava.auth.AuthService;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the failure-counting/locking rules under concurrency.
 *
 * <p>The key concurrency requirement is that N simultaneous wrong-password
 * attempts collapse to exactly N counted failures (never lost, never
 * overwritten), so the lock triggers at exactly {@code maxFailures} with no
 * off-by-N. Lockout and rate limiting must also produce distinguishable
 * outcomes from a plain bad-credential rejection.
 */
class LoginConcurrencyTest {

    private static final String SECRET =
            "concurrent-test-secret-key-at-least-32-bytes-long-01";
    private static final int MAX_FAILURES = 5;
    private static final long LOCK_MILLIS = 300_000;
    private static final int MAX_WINDOW_ATTEMPTS = 10;
    private static final long WINDOW_MILLIS = 600_000;

    private final AtomicLong clock = new AtomicLong(5_000_000L);

    private LoginRateLimiter limiter;
    private AuthService authService;
    private UserRepository users;

    @BeforeEach
    void setUp() throws Exception {
        TimeSource timeSource = clock::get;
        limiter = new LoginRateLimiter(timeSource, MAX_FAILURES, LOCK_MILLIS,
                MAX_WINDOW_ATTEMPTS, WINDOW_MILLIS);

        PasswordEncoder encoder = new PasswordEncoder(10_000);
        TokenService tokenService = new TokenService(
                SECRET, 60_000, 600_000, timeSource);
        TokenRevocationService revocation = new TokenRevocationService();
        users = UserRepository.empty(encoder);
        users.save(new User("bob", encoder.encode("correct-horse"),
                Set.of(Role.VIEWER), Set.of(), true));
        users.save(new User("carol", encoder.encode("correct-horse"),
                Set.of(Role.VIEWER), Set.of(), true));
        authService = new AuthService(users, encoder, tokenService,
                revocation, limiter);
    }

    private LoginError attemptLogin(String user, String password) {
        try {
            authService.login(user, password);
            return null;
        } catch (LoginException e) {
            return e.getError();
        }
    }

    @Nested
    @DisplayName("串行失败计数与三种结果的区分")
    class SequentialSemantics {

        @Test
        @DisplayName("错误密码 -> BAD_CREDENTIALS 且失败次数累加")
        void wrongPasswordIsBadCredentialsAndCounted() {
            LoginError first = attemptLogin("bob", "wrong");
            assertEquals(LoginError.BAD_CREDENTIALS, first);
            assertEquals(1, limiter.consecutiveFailures("bob"));

            assertEquals(LoginError.BAD_CREDENTIALS, attemptLogin("bob", "nope"));
            assertEquals(2, limiter.consecutiveFailures("bob"));
        }

        @Test
        @DisplayName("达到阈值后下一次 -> ACCOUNT_LOCKED, 与 BAD_CREDENTIALS 可区分")
        void lockoutAfterThresholdIsDistinguishable() {
            for (int i = 0; i < MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS, attemptLogin("bob", "wrong"));
            }
            assertEquals(MAX_FAILURES, limiter.consecutiveFailures("bob"));

            // Even the correct password is refused while locked, with a
            // distinct reason (not BAD_CREDENTIALS).
            LoginException locked = assertThrows(LoginException.class,
                    () -> authService.login("bob", "correct-horse"));
            assertEquals(LoginError.ACCOUNT_LOCKED, locked.getError());
        }

        @Test
        @DisplayName("锁定窗口过期后计数归零, 正确密码可重新登录")
        void lockExpiresAndCountersReset() {
            for (int i = 0; i < MAX_FAILURES; i++) {
                attemptLogin("bob", "wrong");
            }
            assertEquals(LoginError.ACCOUNT_LOCKED, attemptLogin("bob", "correct-horse"));

            clock.addAndGet(LOCK_MILLIS + 1);
            assertEquals(0, limiter.consecutiveFailures("bob"));
            TokenPair pair = authService.login("bob", "correct-horse");
            assertNotNull(pair.accessToken());
        }

        @Test
        @DisplayName("成功登录会清空连续失败计数")
        void successResetsCounter() {
            attemptLogin("bob", "wrong");
            attemptLogin("bob", "wrong");
            TokenPair pair = authService.login("bob", "correct-horse");
            assertNotNull(pair);
            assertEquals(0, limiter.consecutiveFailures("bob"));
        }

        @Test
        @DisplayName("窗口内累计失败超过限流阈值 -> RATE_LIMITED, 与锁定/凭据错误均可区分")
        void rateLimitIsDistinguishable() {
            // Cycle 1: five failures lock the account.
            for (int i = 0; i < MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS, attemptLogin("carol", "wrong"));
            }
            // Still inside the lock -> ACCOUNT_LOCKED (distinct outcome #2).
            // Gate-blocked attempts are not credential failures and therefore
            // are not added to the sliding window.
            assertEquals(LoginError.ACCOUNT_LOCKED, attemptLogin("carol", "x"));

            // Let the lock expire but stay inside the sliding rate-limit
            // window; the consecutive-failure cycle restarts.
            clock.addAndGet(LOCK_MILLIS + 1);
            assertEquals(0, limiter.consecutiveFailures("carol"));

            // Four more failures of the new cycle bring the window to 9; the
            // fifth failure both completes 10 window entries and re-engages
            // the consecutive-failure lock.
            for (int i = 0; i < MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS, attemptLogin("carol", "wrong"));
            }
            assertEquals(MAX_FAILURES, limiter.consecutiveFailures("carol"));
            assertEquals(10, limiter.recentFailureTimes("carol").size());

            // Now both gates are active; rate limiting is evaluated first, so
            // even presenting the correct password yields RATE_LIMITED
            // (distinct outcome #3) rather than ACCOUNT_LOCKED.
            LoginError throttled = attemptLogin("carol", "correct-horse");
            assertEquals(LoginError.RATE_LIMITED, throttled);

            // After the whole window passes, attempts flow normally again.
            clock.addAndGet(WINDOW_MILLIS + 1);
            TokenPair pair = authService.login("carol", "correct-horse");
            assertNotNull(pair.accessToken());
        }

        @Test
        @DisplayName("未知用户名与错误密码统一为 BAD_CREDENTIALS, 但同样被限流")
        void unknownUserIsBadCredentialsButCounted() {
            for (int i = 0; i < MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS, attemptLogin("ghost", "x"));
            }
            assertEquals(LoginError.ACCOUNT_LOCKED, attemptLogin("ghost", "x"));
        }

        @Test
        @DisplayName("禁用账号使用正确密码 -> ACCOUNT_DISABLED 且不计入失败锁定")
        void disabledAccountIsDistinctAndNotLocked() {
            users.save(new User("muted",
                    users.findByUsername("bob").orElseThrow().getPasswordHash(),
                    Set.of(Role.VIEWER), Set.of(), false));
            LoginError error = attemptLogin("muted", "correct-horse");
            assertEquals(LoginError.ACCOUNT_DISABLED, error);
            assertEquals(0, limiter.consecutiveFailures("muted"));
        }
    }

    @Nested
    @DisplayName("并发登录的计数正确性")
    class Concurrency {

        @Test
        @DisplayName("N 个并发错误密码恰好记为 N 次失败, 无丢失/覆盖")
        void concurrentFailuresAreCountedExactly() throws Exception {
            int threads = 32;
            ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            AtomicInteger badCredentials = new AtomicInteger();
            AtomicInteger locked = new AtomicInteger();

            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        LoginError error = attemptLogin("bob", "wrong");
                        if (error == LoginError.BAD_CREDENTIALS) {
                            badCredentials.incrementAndGet();
                        } else if (error == LoginError.ACCOUNT_LOCKED) {
                            locked.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(30, TimeUnit.SECONDS), "concurrent attempts hung");
            pool.shutdownNow();

            // The lock triggers exactly on the MAX_FAILURES-th failure.
            assertEquals(MAX_FAILURES, badCredentials.get(),
                    "exactly the threshold failures should be counted as bad credentials");
            assertEquals(threads - MAX_FAILURES, locked.get(),
                    "all attempts beyond the threshold must observe the lock");
            // No lost increment, no over-count.
            assertEquals(MAX_FAILURES, limiter.consecutiveFailures("bob"));
            List<Long> recorded = limiter.recentFailureTimes("bob");
            assertEquals(MAX_FAILURES, recorded.size(),
                    "recorded failure timestamps must equal counted failures");
        }

        @Test
        @DisplayName("两个不同用户名的并发失败互不串扰")
        void perUserStateDoesNotBleedAcrossUsers() throws Exception {
            int threads = 20;
            ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);

            for (int i = 0; i < threads; i++) {
                String target = (i % 2 == 0) ? "bob" : "carol";
                pool.submit(() -> {
                    try {
                        start.await();
                        attemptLogin(target, "wrong");
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(30, TimeUnit.SECONDS));
            pool.shutdownNow();

            // Each user received exactly 10 attempts => 5 bad + 5 locked,
            // counter pinned at the threshold independently.
            assertEquals(MAX_FAILURES, limiter.consecutiveFailures("bob"));
            assertEquals(MAX_FAILURES, limiter.consecutiveFailures("carol"));
        }
    }
}
