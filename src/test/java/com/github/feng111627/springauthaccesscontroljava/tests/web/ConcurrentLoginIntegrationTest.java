package com.github.feng111627.springauthaccesscontroljava.tests.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.springauthaccesscontroljava.tests.support.AbstractIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * 业务覆盖：HTTP 层并发登录失败时，失败计数、锁定状态不能算错或互相覆盖，
 * 并且 BAD_CREDENTIALS / ACCOUNT_LOCKED / RATE_LIMITED / 成功 可精确分辨。
 */
class ConcurrentLoginIntegrationTest extends AbstractIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    @DisplayName("同一账号 30 个并发错误密码请求：恰好 3 个 BAD_CREDENTIALS，其余 ACCOUNT_LOCKED")
    void concurrentBadLogins() throws Exception {
        int threads = 30;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        List<Callable<String>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int index = i;
            tasks.add(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                MvcResult result = mockMvc.perform(post("/api/auth/login")
                                .header("X-Forwarded-For", "10.10." + (index / 250) + "." + (index + 2))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"username\":\"alice\",\"password\":\"wrong\"}"))
                        .andReturn();
                JsonNode body = JSON.readTree(result.getResponse().getContentAsString());
                return body.get("code").asText();
            });
        }
        List<Future<String>> futures = pool.invokeAll(tasks);
        pool.shutdown();

        int badCredentials = 0;
        int locked = 0;
        for (Future<String> future : futures) {
            String code = future.get(10, TimeUnit.SECONDS);
            if ("BAD_CREDENTIALS".equals(code)) {
                badCredentials++;
            } else if ("ACCOUNT_LOCKED".equals(code)) {
                locked++;
            }
        }
        assertEquals(3, badCredentials, "并发下密码错误计数必须恰好为阈值 3，不能多算/少算");
        assertEquals(27, locked, "其余并发请求必须稳定地读到锁定状态，不能互相覆盖");
    }

    @Test
    @DisplayName("并发风暴后即使全部用正确密码，锁定期内仍然 ACCOUNT_LOCKED，锁过期后可正常登录")
    void lockStableThenRecovery() throws Exception {
        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        List<Callable<Integer>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return mockMvc.perform(post("/api/auth/login")
                                .header("X-Forwarded-For", "172.16.1.10")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"username\":\"bob\",\"password\":\"bad\"}"))
                        .andReturn().getResponse().getStatus();
            });
        }
        List<Future<Integer>> futures = pool.invokeAll(tasks);
        pool.shutdown();
        for (Future<Integer> future : futures) {
            future.get(10, TimeUnit.SECONDS);
        }

        // 锁定状态稳定：正确密码也被拒为 423
        int statusDuringLock = mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "172.16.1.10")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob123\"}"))
                .andReturn().getResponse().getStatus();
        assertEquals(423, statusDuringLock);

        // 锁过期（测试配置为 300 秒）后恢复正常
        attempts.reset();
        MvcResult after = mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "172.16.1.10")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob123\"}"))
                .andReturn();
        assertEquals(200, after.getResponse().getStatus());
        assertTrue(JSON.readTree(after.getResponse().getContentAsString())
                .get("accessToken").asText().contains("."));
    }

    @Test
    @DisplayName("单 IP 高并发不同账号失败达到 IP 阈值 -> RATE_LIMITED，且与账号锁定错误码不同")
    void ipRateLimitUnderConcurrency() throws Exception {
        int threads = 10;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        List<Callable<Integer>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final String username = "user-" + i;
            tasks.add(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                return mockMvc.perform(post("/api/auth/login")
                                .header("X-Forwarded-For", "172.16.2.20")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"username\":\"" + username + "\",\"password\":\"bad\"}"))
                        .andReturn().getResponse().getStatus();
            });
        }
        pool.invokeAll(tasks).forEach(f -> {
            try {
                f.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        pool.shutdown();

        // 窗口内已失败 10 次（阈值），下一次请求（任意账号）应被 IP 限流
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "172.16.2.20")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice123\"}"))
                .andReturn();
        assertEquals(429, result.getResponse().getStatus());
        JsonNode body = JSON.readTree(result.getResponse().getContentAsString());
        assertEquals("RATE_LIMITED", body.get("code").asText());
    }
}
