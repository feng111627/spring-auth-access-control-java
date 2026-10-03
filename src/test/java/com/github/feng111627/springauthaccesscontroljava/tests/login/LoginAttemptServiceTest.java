package com.github.feng111627.springauthaccesscontroljava.tests.login;

import com.github.feng111627.springauthaccesscontroljava.config.AuthProperties;
import com.github.feng111627.springauthaccesscontroljava.config.MutableClock;
import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import com.github.feng111627.springauthaccesscontroljava.login.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务覆盖：账号短时锁定、锁定到期恢复、登录成功清零、来源 IP 滑动窗口限流，
 * 以及高并发登录失败时计数与锁定状态的一致性（不能多算、少算或互相覆盖）。
 */
class LoginAttemptServiceTest {

    private MutableClock clock;
    private AuthProperties properties;
    private LoginAttemptService attempts;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        clock.freezeAt(Instant.parse("2026-10-03T00:00:00Z"));
        properties = new AuthProperties();
        properties.setMaxLoginFailures(3);
        properties.setLockDuration(Duration.ofSeconds(300));
        properties.setIpMaxFailures(10);
        properties.setIpWindow(Duration.ofSeconds(60));
        attempts = new LoginAttemptService(properties, clock);
    }

    @Test
    @DisplayName("未达阈值的失败仍可继续尝试，不被锁定")
    void belowThresholdNotLocked() {
        attempts.assertLoginAllowed("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.assertLoginAllowed("alice", "1.1.1.1"); // 不抛异常
    }

    @Test
    @DisplayName("第 3 次失败后，下一次尝试即 ACCOUNT_LOCKED，且带剩余锁定秒数")
    void lockAfterThreshold() {
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        ApiException ex = assertThrows(ApiException.class,
                () -> attempts.assertLoginAllowed("alice", "1.1.1.1"));
        assertEquals(ErrorCode.ACCOUNT_LOCKED, ex.code());
        assertEquals(300L, ex.details().get("retryAfterSeconds"));
    }

    @Test
    @DisplayName("锁定期满自动解锁并重新计数")
    void lockExpires() {
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        assertThrows(ApiException.class, () -> attempts.assertLoginAllowed("alice", "1.1.1.1"));

        clock.advance(Duration.ofSeconds(301));
        attempts.assertLoginAllowed("alice", "1.1.1.1"); // 锁过期，放行
        // 重新开始计数：再失败 3 次才会再次锁定
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.assertLoginAllowed("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        assertEquals(ErrorCode.ACCOUNT_LOCKED,
                assertThrows(ApiException.class,
                        () -> attempts.assertLoginAllowed("alice", "1.1.1.1")).code());
    }

    @Test
    @DisplayName("登录成功清零失败计数，不会带着历史失败被锁")
    void successClearsFailures() {
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordSuccess("alice");
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.assertLoginAllowed("alice", "1.1.1.1"); // 仅 2 次，放行
    }

    @Test
    @DisplayName("不同账号的失败计数互不影响")
    void accountsIsolated() {
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        attempts.recordFailure("alice", "1.1.1.1");
        // bob 从 0 开始
        attempts.assertLoginAllowed("bob", "1.1.1.1");
        attempts.recordFailure("bob", "1.1.1.1");
    }

    @Test
    @DisplayName("同一 IP 滑动窗口内失败超限 -> RATE_LIMITED，与账号锁定可区分")
    void ipRateLimit() {
        for (int i = 0; i < 10; i++) {
            // 每次换账号，避免触发账号锁定；同一 IP 累计失败
            attempts.recordFailure("user-" + i, "9.9.9.9");
        }
        ApiException ex = assertThrows(ApiException.class,
                () -> attempts.assertLoginAllowed("anyone", "9.9.9.9"));
        assertEquals(ErrorCode.RATE_LIMITED, ex.code());
        // 不同 IP 不受影响
        attempts.assertLoginAllowed("anyone", "8.8.8.8");
    }

    @Test
    @DisplayName("IP 窗口滑过后失败计数过期，不再限流")
    void ipWindowSlides() {
        for (int i = 0; i < 10; i++) {
            attempts.recordFailure("user-" + i, "9.9.9.9");
        }
        clock.advance(Duration.ofSeconds(61));
        attempts.assertLoginAllowed("anyone", "9.9.9.9");
    }

    @Test
    @DisplayName("并发 20 次同时失败：恰好 3 次计入失败、其余 17 次撞上锁定，计数绝不漂移")
    void concurrentFailuresCountExactly() throws Exception {
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        List<Callable<ErrorCode>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                String perThreadIp = "1.1.1." + (Math.abs(Thread.currentThread().hashCode()) % 200 + 2);
                try {
                    // 与生产登录一致的原子路径：锁定复查 + 失败计数在同一把账号锁内
                    attempts.registerCredentialFailure("alice", perThreadIp);
                    return ErrorCode.BAD_CREDENTIALS;
                } catch (ApiException gate) {
                    return gate.code();
                }
            });
        }
        List<Future<ErrorCode>> futures = pool.invokeAll(tasks);
        pool.shutdown();
        int badCredentials = 0;
        int locked = 0;
        for (Future<ErrorCode> future : futures) {
            ErrorCode code = future.get(5, TimeUnit.SECONDS);
            if (code == ErrorCode.BAD_CREDENTIALS) {
                badCredentials++;
            } else if (code == ErrorCode.ACCOUNT_LOCKED) {
                locked++;
            }
        }
        // 恰好前 3 个通过闸门并记失败；其余请求全部在闸门处看到锁定
        assertEquals(3, badCredentials, "被计为失败的次数必须恰好为阈值 3");
        assertEquals(17, locked, "其余并发请求必须全部撞上 ACCOUNT_LOCKED");
        // 锁定之后，后续请求依然稳定地被拒绝，不会出现计数回退（换 IP 以隔离 IP 限流维度）
        assertEquals(ErrorCode.ACCOUNT_LOCKED,
                assertThrows(ApiException.class,
                        () -> attempts.assertLoginAllowed("alice", "5.5.5.5")).code());
        assertTrue(locked + badCredentials == threads);
    }
}
