package com.github.feng111627.springauthaccesscontroljava.tests.support;

import com.github.feng111627.springauthaccesscontroljava.auth.Pbkdf2PasswordEncoder;
import com.github.feng111627.springauthaccesscontroljava.config.MutableClock;
import com.github.feng111627.springauthaccesscontroljava.login.LoginAttemptService;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import com.github.feng111627.springauthaccesscontroljava.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

/**
 * 集成测试基类：每个用例前重置内存数据（用户、失败计数、时钟），
 * 保证用例之间互不污染，令牌版本/权限/锁定状态始终从确定初态开始。
 */
@SpringBootTest
@AutoConfigureMockMvc
public abstract class AbstractIntegrationTest {

    @Autowired protected MockMvc mockMvc;
    @Autowired protected UserRepository users;
    @Autowired protected Pbkdf2PasswordEncoder encoder;
    @Autowired protected LoginAttemptService attempts;
    @Autowired protected MutableClock clock;

    @BeforeEach
    void resetSharedState() {
        attempts.reset();
        clock.unfreeze();
        users.resetForTesting();
        seed();
    }

    private void seed() {
        put("admin", "admin123", Set.of("ADMIN"), Set.of("user:admin", "report:read"), UserStatus.ACTIVE);
        put("alice", "alice123", Set.of("USER"), Set.of("report:read"), UserStatus.ACTIVE);
        put("bob", "bob123", Set.of("USER"), Set.of(), UserStatus.ACTIVE);
        put("nancy", "nancy123", Set.of("USER"), Set.of(), UserStatus.DISABLED);
    }

    private void put(String username, String password, Set<String> roles,
                     Set<String> permissions, UserStatus status) {
        User user = users.create(username, encoder.encode(password), roles, permissions);
        user.setStatus(status);
    }
}
