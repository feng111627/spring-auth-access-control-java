package com.github.feng111627.springauthaccesscontroljava.tests.login;

import com.github.feng111627.springauthaccesscontroljava.auth.AuthService;
import com.github.feng111627.springauthaccesscontroljava.login.LoginError;
import com.github.feng111627.springauthaccesscontroljava.login.LoginException;
import com.github.feng111627.springauthaccesscontroljava.login.LoginRateLimiter;
import com.github.feng111627.springauthaccesscontroljava.security.PasswordEncoder;
import com.github.feng111627.springauthaccesscontroljava.security.TimeSource;
import com.github.feng111627.springauthaccesscontroljava.security.TokenRevocationService;
import com.github.feng111627.springauthaccesscontroljava.security.TokenService;
import com.github.feng111627.springauthaccesscontroljava.user.Role;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

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

/**
 * Source-dimension login protection: failures aggregated per source across
 * usernames (unknown ones included), independent reachability of both
 * dimensions, fixed priority when both trip, and exact concurrent counting.
 */
class SourceLoginProtectionTest {

    private static final String SECRET =
            "source-test-secret-key-at-least-32-bytes-long-0001";
    private static final int MAX_FAILURES = 5;
    private static final long LOCK_MILLIS = 600_000;
    private static final int MAX_USER_WINDOW = 1000; // user-window off here
    private static final long USER_WINDOW_MILLIS = 600_000;
    private static final int MAX_SOURCE_FAILURES = 8;
    private static final long SOURCE_WINDOW_MILLIS = 300_000;

    private final AtomicLong clock = new AtomicLong(9_000_000L);

    private LoginRateLimiter limiter;
    private AuthService authService;

    @BeforeEach
    void setUp() throws Exception {
        TimeSource timeSource = clock::get;
        limiter = new LoginRateLimiter(timeSource, MAX_FAILURES, LOCK_MILLIS,
                MAX_USER_WINDOW, USER_WINDOW_MILLIS,
                MAX_SOURCE_FAILURES, SOURCE_WINDOW_MILLIS);

        PasswordEncoder encoder = new PasswordEncoder(10_000);
        TokenService tokenService = new TokenService(
                SECRET, 60_000, 600_000, timeSource);
        TokenRevocationService revocation = new TokenRevocationService();
        UserRepository users = UserRepository.empty(encoder);
        users.save(new User("bob", encoder.encode("correct-horse"),
                Set.of(Role.VIEWER), Set.of(), true));
        authService = new AuthService(users, encoder, tokenService,
                revocation, limiter);
    }

    private LoginError attempt(String source, String username, String password) {
        try {
            authService.login(source, username, password);
            return null;
        } catch (LoginException e) {
            return e.getError();
        }
    }

    @Nested
    @DisplayName("来源维度触发限流")
    class SourceDimension {

        @Test
        @DisplayName("同一来源轮换不同用户名(含不存在的)打到来源阈值 -> SOURCE_RATE_LIMITED, 与锁定/密码错可分辨")
        void sprayingDifferentUsernamesFromOneSourceGetsThrottled() {
            String source = "10.0.0.1";
            // Every username is probed only once, so no account can ever lock;
            // most usernames do not even exist.
            for (int i = 0; i < MAX_SOURCE_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt(source, "ghost-" + i, "x"),
                        "attempt " + i + " is still an ordinary credential failure");
            }
            assertEquals(MAX_SOURCE_FAILURES,
                    limiter.sourceWindowFailureCount(source));

            // The 9th attempt, even against yet another fresh username, is
            // rejected purely on the source dimension with its own result.
            LoginException blocked = assertThrows(LoginException.class,
                    () -> authService.login(source, "totally-new", "x"));
            assertEquals(LoginError.SOURCE_RATE_LIMITED, blocked.getError());

            // Gate-blocked attempts must not feed the window further.
            assertEquals(MAX_SOURCE_FAILURES,
                    limiter.sourceWindowFailureCount(source));
        }

        @Test
        @DisplayName("不同来源互不影响: A 来源已被限流, B 来源同批用户名仍得到 BAD_CREDENTIALS")
        void otherSourcesAreNotAffected() {
            String blocked = "10.0.0.1";
            for (int i = 0; i < MAX_SOURCE_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt(blocked, "ghost-" + i, "x"));
            }
            assertEquals(LoginError.SOURCE_RATE_LIMITED,
                    attempt(blocked, "ghost-x", "x"));

            // A fresh source starts with an empty bucket and is not throttled.
            assertEquals(LoginError.BAD_CREDENTIALS,
                    attempt("10.0.0.2", "ghost-0", "x"));
            assertEquals(1, limiter.sourceWindowFailureCount("10.0.0.2"));
            assertEquals(MAX_SOURCE_FAILURES,
                    limiter.sourceWindowFailureCount(blocked));
        }

        @Test
        @DisplayName("来源窗口到期后自动恢复")
        void sourceWindowExpiresAndRecovers() {
            String source = "10.0.0.3";
            for (int i = 0; i < MAX_SOURCE_FAILURES; i++) {
                attempt(source, "ghost-" + i, "x");
            }
            assertEquals(LoginError.SOURCE_RATE_LIMITED,
                    attempt(source, "ghost-z", "x"));

            clock.addAndGet(SOURCE_WINDOW_MILLIS + 1);
            assertEquals(0, limiter.sourceWindowFailureCount(source));
            assertEquals(LoginError.BAD_CREDENTIALS,
                    attempt(source, "ghost-z", "x"));
        }

        @Test
        @DisplayName("某账号登录成功不会清空该来源的跨账号失败窗口")
        void successDoesNotResetSourceWindow() {
            String source = "10.0.0.4";
            for (int i = 0; i < MAX_SOURCE_FAILURES - 1; i++) {
                attempt(source, "ghost-" + i, "x");
            }
            // A successful login for a real account from the same source.
            assertNotNull(authService.login(source, "bob", "correct-horse")
                    .accessToken());
            // Source evidence survives someone else logging in successfully.
            assertEquals(MAX_SOURCE_FAILURES - 1,
                    limiter.sourceWindowFailureCount(source));

            // One more cross-username failure fills the bucket.
            assertEquals(LoginError.BAD_CREDENTIALS,
                    attempt(source, "ghost-final", "x"));
            assertEquals(LoginError.SOURCE_RATE_LIMITED,
                    attempt(source, "anything", "x"));
        }
    }

    @Nested
    @DisplayName("两个维度各自独立可触发 / 同时触发时优先级固定")
    class IndependenceAndPriority {

        @Test
        @DisplayName("账号维度: 同一账号每次换不同来源打到锁定, 任何来源桶都未到来源阈值 -> 仍可 ACCOUNT_LOCKED")
        void accountLockReachableWhenSourceEachStaysBelowThreshold() {
            // Five failures for one username, each from a distinct source:
            // no source bucket ever exceeds 1 failure.
            for (int i = 0; i < MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt("172.16.0." + i, "bob", "wrong"));
            }
            // A sixth source still observes the account lock; the source
            // dimension never trips here.
            LoginException locked = assertThrows(LoginException.class,
                    () -> authService.login("172.16.0.99", "bob", "correct-horse"));
            assertEquals(LoginError.ACCOUNT_LOCKED, locked.getError());
            assertEquals(MAX_FAILURES, limiter.consecutiveFailures("bob"));
            assertEquals(0, limiter.sourceWindowFailureCount("172.16.0.99"));
        }

        @Test
        @DisplayName("两维同时满足时: 来源限流优先(429 SOURCE_RATE_LIMITED); 来源窗口过后账号锁仍在(423)")
        void sourceGateWinsWhenBothActiveAndLockSurvivesAfterwards() {
            String source = "192.168.1.10";

            // Build the ACCOUNT lock using sources OTHER than 'source', so the
            // account is locked without touching source's own bucket.
            for (int i = 0; i < MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt("other-" + i, "bob", "wrong"));
            }
            assertEquals(LoginError.ACCOUNT_LOCKED,
                    attempt("other-99", "bob", "x"));

            // Independently fill the source bucket via username spray.
            for (int i = 0; i < MAX_SOURCE_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt(source, "spray-" + i, "x"));
            }

            // Both gates active at once -> the fixed priority must select the
            // source gate, deterministically, for every attempt from source.
            for (int i = 0; i < 5; i++) {
                assertEquals(LoginError.SOURCE_RATE_LIMITED,
                        attempt(source, "bob", "correct-horse"));
            }

            // After the source window slides away the account lock is still
            // active: the account dimension was never "replaced" by the source
            // gate, just outranked while both were active.
            clock.addAndGet(SOURCE_WINDOW_MILLIS + 1);
            assertEquals(LoginError.ACCOUNT_LOCKED,
                    attempt(source, "bob", "correct-horse"));
        }

        @Test
        @DisplayName("锁定期内从同一来源继续刷不同用户名, 来源计数照样增长并最终被来源维度拦下")
        void sourceBucketStillFillsWhileAnotherAccountIsLocked() {
            String source = "192.168.1.20";
            for (int i = 0; i < MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt(source, "bob", "wrong"));
            }
            // bob is locked from this source; subsequent bob attempts return
            // ACCOUNT_LOCKED and are not counted...
            assertEquals(LoginError.ACCOUNT_LOCKED,
                    attempt(source, "bob", "x"));
            assertEquals(MAX_FAILURES, limiter.sourceWindowFailureCount(source));

            // ...but spraying other usernames still accumulates source failures.
            for (int i = 0; i < MAX_SOURCE_FAILURES - MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt(source, "other-" + i, "x"));
            }
            assertEquals(LoginError.SOURCE_RATE_LIMITED,
                    attempt(source, "bob", "x"));
        }
    }

    @Nested
    @DisplayName("并发下两个维度的计数正确性")
    class Concurrency {

        @Test
        @DisplayName("同一来源并发轮换用户名: 恰好 MAX_SOURCE_FAILURES 次 BAD_CREDENTIALS, 其余全部 SOURCE_RATE_LIMITED")
        void concurrentSprayFromOneSourceCountedExactly() throws Exception {
            int threads = 40;
            ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            AtomicInteger bad = new AtomicInteger();
            AtomicInteger throttled = new AtomicInteger();
            AtomicInteger other = new AtomicInteger();

            for (int i = 0; i < threads; i++) {
                String username = "spray-user-" + i; // distinct per thread
                pool.submit(() -> {
                    try {
                        start.await();
                        LoginError error = attempt("10.1.0.1", username, "x");
                        if (error == LoginError.BAD_CREDENTIALS) {
                            bad.incrementAndGet();
                        } else if (error == LoginError.SOURCE_RATE_LIMITED) {
                            throttled.incrementAndGet();
                        } else {
                            other.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertEquals(true, done.await(30, TimeUnit.SECONDS), "hung");
            pool.shutdownNow();

            assertEquals(0, other.get(), "no third, contradictory verdict");
            assertEquals(MAX_SOURCE_FAILURES, bad.get(),
                    "exactly the threshold credential failures get through");
            assertEquals(threads - MAX_SOURCE_FAILURES, throttled.get(),
                    "every later attempt is source-throttled");
            assertEquals(MAX_SOURCE_FAILURES,
                    limiter.sourceWindowFailureCount("10.1.0.1"),
                    "no lost/duplicated increment in the source window");
        }

        @Test
        @DisplayName("同一账号并发但来源各不相同: 恰好 5 次 BAD_CREDENTIALS, 其余全部 ACCOUNT_LOCKED, 来源维度不串扰")
        void concurrentSameAccountFromDistinctSourcesLocksExactly()
                throws Exception {
            int threads = 24;
            ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            AtomicInteger bad = new AtomicInteger();
            AtomicInteger locked = new AtomicInteger();
            AtomicInteger other = new AtomicInteger();

            for (int i = 0; i < threads; i++) {
                String source = "10.2.0." + i; // each source used exactly once
                pool.submit(() -> {
                    try {
                        start.await();
                        LoginError error = attempt(source, "bob", "wrong");
                        if (error == LoginError.BAD_CREDENTIALS) {
                            bad.incrementAndGet();
                        } else if (error == LoginError.ACCOUNT_LOCKED) {
                            locked.incrementAndGet();
                        } else {
                            other.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertEquals(true, done.await(30, TimeUnit.SECONDS), "hung");
            pool.shutdownNow();

            assertEquals(0, other.get(), "no source throttling may appear");
            assertEquals(MAX_FAILURES, bad.get());
            assertEquals(threads - MAX_FAILURES, locked.get());
            assertEquals(MAX_FAILURES, limiter.consecutiveFailures("bob"));
        }

        @Test
        @DisplayName("两维同时生效时并发请求结论一致: 同一时刻只可能得到 SOURCE_RATE_LIMITED, 不会夹杂 ACCOUNT_LOCKED")
        void concurrentVerdictIsConsistentWhenBothGatesActive() throws Exception {
            String source = "10.3.0.1";
            // Pre-load BOTH gates deterministically before the concurrent phase.
            for (int i = 0; i < MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt("seed-" + i, "bob", "wrong"));
            }
            for (int i = 0; i < MAX_SOURCE_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt(source, "seed-spray-" + i, "x"));
            }

            int threads = 32;
            ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            AtomicInteger throttled = new AtomicInteger();
            AtomicInteger contradictions = new AtomicInteger();

            for (int i = 0; i < threads; i++) {
                String username = (i % 2 == 0) ? "bob" : "mixed-" + i;
                pool.submit(() -> {
                    try {
                        start.await();
                        LoginError error = attempt(source, username, "x");
                        if (error == LoginError.SOURCE_RATE_LIMITED) {
                            throttled.incrementAndGet();
                        } else {
                            contradictions.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertEquals(true, done.await(30, TimeUnit.SECONDS), "hung");
            pool.shutdownNow();

            assertEquals(threads, throttled.get(),
                    "all concurrent attempts must agree on one verdict");
            assertEquals(0, contradictions.get(),
                    "no attempt may look both throttled and locked");
            // The blocked phase must not have mutated either counter.
            assertEquals(MAX_SOURCE_FAILURES,
                    limiter.sourceWindowFailureCount(source));
            assertEquals(MAX_FAILURES, limiter.consecutiveFailures("bob"));
        }
    }
}
