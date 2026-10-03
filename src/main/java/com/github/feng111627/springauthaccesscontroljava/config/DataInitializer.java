package com.github.feng111627.springauthaccesscontroljava.config;

import com.github.feng111627.springauthaccesscontroljava.auth.Pbkdf2PasswordEncoder;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import com.github.feng111627.springauthaccesscontroljava.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

/**
 * 本地演示数据（密码均经 PBKDF2 哈希存储）：
 * <ul>
 *   <li>admin / admin123：ADMIN 角色，user:admin + report:read 权限</li>
 *   <li>alice / alice123：USER 角色，report:read 权限</li>
 *   <li>bob   / bob123：  USER 角色，无特殊权限（用于 403 演示）</li>
 *   <li>nancy / nancy123：USER 角色，已停用（用于 ACCOUNT_DISABLED 演示）</li>
 * </ul>
 */
@Configuration
public class DataInitializer {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    CommandLineRunner seedUsers(UserRepository users, Pbkdf2PasswordEncoder encoder) {
        return args -> {
            createIfAbsent(users, encoder, "admin", "admin123",
                    Set.of("ADMIN"), Set.of("user:admin", "report:read"), UserStatus.ACTIVE);
            createIfAbsent(users, encoder, "alice", "alice123",
                    Set.of("USER"), Set.of("report:read"), UserStatus.ACTIVE);
            createIfAbsent(users, encoder, "bob", "bob123",
                    Set.of("USER"), Set.of(), UserStatus.ACTIVE);
            createIfAbsent(users, encoder, "nancy", "nancy123",
                    Set.of("USER"), Set.of(), UserStatus.DISABLED);
            log.info("演示账号初始化完成: admin/admin123, alice/alice123, bob/bob123, nancy(停用)/nancy123");
        };
    }

    private void createIfAbsent(UserRepository users, Pbkdf2PasswordEncoder encoder,
                                String username, String rawPassword,
                                Set<String> roles, Set<String> permissions, UserStatus status) {
        if (users.findByUsername(username).isPresent()) {
            return;
        }
        User user = users.create(username, encoder.encode(rawPassword), roles, permissions);
        user.setStatus(status);
    }
}
