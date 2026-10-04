package com.github.feng111627.springauthaccesscontroljava.tests.login;

import com.github.feng111627.springauthaccesscontroljava.auth.AuthService;
import com.github.feng111627.springauthaccesscontroljava.login.LoginError;
import com.github.feng111627.springauthaccesscontroljava.login.LoginException;
import com.github.feng111627.springauthaccesscontroljava.login.LoginRateLimiter;
import com.github.feng111627.springauthaccesscontroljava.login.SourceRateLimiter;
import com.github.feng111627.springauthaccesscontroljava.security.PasswordEncoder;
import com.github.feng111627.springauthaccesscontroljava.security.TimeSource;
import com.github.feng111627.springauthaccesscontroljava.security.TokenPair;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the per-source (client) failure aggregation dimension:
 *
 * <ul>
 *   <li>failures from one source are summed across all usernames, including
 *       non-existent ones, and trip {@code SOURCE_RATE_LIMITED} — a result
 *       distinguishable from both {@code BAD_CREDENTIALS} and
 *       {@code ACCOUNT_LOCKED};</li>
 *   <li>the account dimension and the source dimension are independent and
 *       each is actually reachable; when both trip on the same attempt the
 *       account dimension wins, consistently;</li>
 *   <li>under high concurrency the source counters are exact and the two
 *       dimensions never produce contradictory outcomes.</li>
 * </ul>
 */
class SourceRateLimitTest {

    private static final String SECRET =
            "source-limit-test-secret-key-at-least-32-bytes-long";
    private static final int MAX_FAILURES = 3;
    private static final long LOCK_MILLIS = 300_000;
    // Keep the per-username sliding window unreachable so only the
    // consecutive-failure lockout represents the account dimension here.
    private static final int UNREACHABLE_USER_WINDOW = 1_000_000;
    private static final int SOURCE_LIMIT = 5;
    private static final long WINDOW_MILLIS = 600_000;

    private final AtomicLong clock = new AtomicLong(7_000_000L);

    private LoginRateLimiter accountLimiter;
    private SourceRateLimiter sourceLimiter;
    private AuthService authService;

    @BeforeEach
    void setUp() throws Exception {
        TimeSource timeSource = clock::get;
        accountLimiter = new LoginRateLimiter(timeSource, MAX_FAILURES, LOCK_MILLIS,
                UNREACHABLE_USER_WINDOW, WINDOW_MILLIS);
        sourceLimiter = new SourceRateLimiter(timeSource, SOURCE_LIMIT, WINDOW_MILLIS);

        PasswordEncoder encoder = new PasswordEncoder(10_000);
        TokenService tokenService = new TokenService(
                SECRET, 60_000, 600_000, timeSource);
        TokenRevocationService revocation = new TokenRevocationService();
        UserRepository users = UserRepository.empty(encoder);
        users.save(new User("alice", encoder.encode("correct-horse"),
                Set.of(Role.VIEWER), Set.of(), true));
        users.save(new User("frank", encoder.encode("correct-horse"),
                Set.of(Role.VIEWER), Set.of(), true));
        authService = new AuthService(users, encoder, tokenService,
                revocation, accountLimiter, sourceLimiter);
    }

    private LoginError attempt(String user, String password, String source) {
        try {
            authService.login(user, password, source);
            return null;
        } catch (LoginException e) {
            return e.getError();
        }
    }

    @Nested
    @DisplayName("来源维度聚合与可区分性")
    class SourceAggregation {

        @Test
        @DisplayName("同一来源轮换用户名(含不存在用户)聚合触发 SOURCE_RATE_LIMITED, 与锁定/凭据错误可区分")
        void rotatingUsernamesFromOneSourceTripsSourceLimit() {
            String src = "10.0.0.1";
            // Mix existing and non-existent usernames; each stays far below
            // the per-account threshold, so the account dimension never trips.
            String[] usernames = {"alice", "ghost-1", "ghost-2", "frank", "ghost-3"};
            for (String username : usernames) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt(username, "bad", src));
            }
            assertEquals(SOURCE_LIMIT, sourceLimiter.recentFailureCount(src));
            // No account got locked: every username saw a single failure.
            assertEquals(1, accountLimiter.consecutiveFailures("alice"));

            // The next attempt from this source is throttled as a whole —
            // even with the correct password for an existing, unlocked
            // account — and the outcome is neither BAD_CREDENTIALS nor
            // ACCOUNT_LOCKED.
            LoginError throttled = attempt("alice", "correct-horse", src);
            assertEquals(LoginError.SOURCE_RATE_LIMITED, throttled);

            // Gate-blocked attempts are not recorded: the window stays at 5.
            assertEquals(SOURCE_LIMIT, sourceLimiter.recentFailureCount(src));
        }

        @Test
        @DisplayName("来源限流不波及其他来源: 换个来源同一账号仍可正常登录")
        void sourceLimitDoesNotAffectOtherSources() {
            String hot = "10.0.0.2";
            for (int i = 0; i < SOURCE_LIMIT; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt("ghost-" + i, "bad", hot));
            }
            assertEquals(LoginError.SOURCE_RATE_LIMITED,
                    attempt("alice", "correct-horse", hot));

            // A different source is untouched and can log alice in.
            TokenPair pair = authService.login("alice", "correct-horse", "10.0.0.3");
            assertNotNull(pair.accessToken());
        }

        @Test
        @DisplayName("来源窗口过期后自动恢复")
        void sourceWindowExpires() {
            String src = "10.0.0.4";
            for (int i = 0; i < SOURCE_LIMIT; i++) {
                attempt("ghost-" + i, "bad", src);
            }
            assertEquals(LoginError.SOURCE_RATE_LIMITED,
                    attempt("alice", "correct-horse", src));

            clock.addAndGet(WINDOW_MILLIS + 1);
            assertEquals(0, sourceLimiter.recentFailureCount(src));
            TokenPair pair = authService.login("alice", "correct-horse", src);
            assertNotNull(pair.accessToken());
        }

        @Test
        @DisplayName("登录成功不清空来源窗口: 之前的爆破失败仍然计数")
        void successDoesNotClearSourceWindow() {
            String src = "10.0.0.5";
            for (int i = 0; i < SOURCE_LIMIT - 1; i++) {
                attempt("ghost-" + i, "bad", src);
            }
            // A legitimate success from the same source...
            TokenPair pair = authService.login("alice", "correct-horse", src);
            assertNotNull(pair.accessToken());
            // ...does not erase the preceding burst: one more failure fills
            // the window and the source is throttled.
            assertEquals(LoginError.BAD_CREDENTIALS, attempt("ghost-x", "bad", src));
            assertEquals(LoginError.SOURCE_RATE_LIMITED,
                    attempt("alice", "correct-horse", src));
        }
    }

    @Nested
    @DisplayName("两个维度各自独立且优先级固定")
    class IndependenceAndPriority {

        @Test
        @DisplayName("账号维度独立可触发: 未触及来源阈值时仍能锁定单个账号")
        void accountLockTriggersWithoutSourceLimit() {
            String src = "10.1.0.1";
            for (int i = 0; i < MAX_FAILURES; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt("alice", "bad", src));
            }
            // Source window (3 of 5) is not full, yet the account locks.
            assertEquals(LoginError.ACCOUNT_LOCKED,
                    attempt("alice", "correct-horse", src));
            assertTrue(sourceLimiter.recentFailureCount(src) < SOURCE_LIMIT);
        }

        @Test
        @DisplayName("来源维度独立可触发: 所有账号都在阈值以下时整体限流")
        void sourceLimitTriggersWithoutAnyAccountLock() {
            String src = "10.1.0.2";
            for (int i = 0; i < SOURCE_LIMIT; i++) {
                assertEquals(LoginError.BAD_CREDENTIALS,
                        attempt("ghost-" + i, "bad", src));
            }
            assertEquals(LoginError.SOURCE_RATE_LIMITED,
                    attempt("ghost-next", "bad", src));
            // No username ever reached the account threshold.
            assertEquals(1, accountLimiter.consecutiveFailures("ghost-0"));
        }

        @Test
        @DisplayName("两维度同时满足时账号维度优先: 固定返回 ACCOUNT_LOCKED")
        void accountDimensionWinsWhenBothTrip() {
            // Lock frank via a quiet source.
            String quiet = "10.1.0.3";
            for (int i = 0; i < MAX_FAILURES; i++) {
                attempt("frank", "bad", quiet);
            }
            assertEquals(LoginError.ACCOUNT_LOCKED,
                    attempt("frank", "bad", quiet));

            // Fill a different source's window with rotating usernames.
            String hot = "10.1.0.4";
            for (int i = 0; i < SOURCE_LIMIT; i++) {
                attempt("ghost-" + i, "bad", hot);
            }
            // frank is locked AND the source is throttled: the account
            // dimension is evaluated first, so the result is ACCOUNT_LOCKED.
            assertEquals(LoginError.ACCOUNT_LOCKED,
                    attempt("frank", "correct-horse", hot));
            // An unlocked account from the same hot source still gets the
            // source-dimension result — the two outcomes stay distinguishable.
            assertEquals(LoginError.SOURCE_RATE_LIMITED,
                    attempt("alice", "correct-horse", hot));
        }
    }

    @Nested
    @DisplayName("并发下来源维度计数正确")
    class Concurrency {

        @Test
        @DisplayName("同一来源 32 线程并发失败: 恰好阈值次数计入, 其余全部 SOURCE_RATE_LIMITED")
        void concurrentSourceFailuresCountedExactly() throws Exception {
            String src = "10.2.0.1";
            int threads = 32;
            ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            AtomicInteger badCredentials = new AtomicInteger();
            AtomicInteger sourceLimited = new AtomicInteger();
            AtomicInteger other = new AtomicInteger();

            for (int i = 0; i < threads; i++) {
                String username = "ghost-" + i; // unique: account dimension never trips
                pool.submit(() -> {
                    try {
                        start.await();
                        LoginError error = attempt(username, "bad", src);
                        if (error == LoginError.BAD_CREDENTIALS) {
                            badCredentials.incrementAndGet();
                        } else if (error == LoginError.SOURCE_RATE_LIMITED) {
                            sourceLimited.incrementAndGet();
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
            assertTrue(done.await(30, TimeUnit.SECONDS), "concurrent attempts hung");
            pool.shutdownNow();

            assertEquals(SOURCE_LIMIT, badCredentials.get(),
                    "exactly the window-size failures are counted");
            assertEquals(threads - SOURCE_LIMIT, sourceLimited.get(),
                    "all attempts beyond the window observe the source throttle");
            assertEquals(0, other.get(), "no contradictory outcome may appear");
            assertEquals(SOURCE_LIMIT, sourceLimiter.recentFailureCount(src),
                    "recorded source failures must equal admitted attempts");
        }

        @Test
        @DisplayName("同账号同来源高并发: 两维度记账一致, 不出现矛盾结论")
        void concurrentSameAccountSameSourceIsConsistent() throws Exception {
            String src = "10.2.0.2";
            int threads = 32;
            ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            AtomicInteger badCredentials = new AtomicInteger();
            AtomicInteger locked = new AtomicInteger();
            AtomicInteger sourceLimited = new AtomicInteger();

            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        LoginError error = attempt("alice", "bad", src);
                        if (error == LoginError.BAD_CREDENTIALS) {
                            badCredentials.incrementAndGet();
                        } else if (error == LoginError.ACCOUNT_LOCKED) {
                            locked.incrementAndGet();
                        } else if (error == LoginError.SOURCE_RATE_LIMITED) {
                            sourceLimited.incrementAndGet();
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

            // Account lock trips at exactly MAX_FAILURES; only those real
            // credential failures reach the source window (3 < 5), so the
            // source dimension must stay silent — no contradictory mix of
            // LOCKED and SOURCE_RATE_LIMITED.
            assertEquals(MAX_FAILURES, badCredentials.get());
            assertEquals(threads - MAX_FAILURES, locked.get());
            assertEquals(0, sourceLimited.get());
            assertEquals(MAX_FAILURES, accountLimiter.consecutiveFailures("alice"));
            assertEquals(MAX_FAILURES, sourceLimiter.recentFailureCount(src));
        }
    }
}
