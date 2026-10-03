package com.github.feng111627.springauthaccesscontroljava.user;

import com.github.feng111627.springauthaccesscontroljava.security.PasswordEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Thread-safe in-memory user store, seeded with demo accounts. */
@Repository
public class UserRepository {

    private static final Logger log = LoggerFactory.getLogger(UserRepository.class);

    private final ConcurrentHashMap<String, User> users = new ConcurrentHashMap<>();
    private final PasswordEncoder passwordEncoder;

    @org.springframework.beans.factory.annotation.Autowired
    public UserRepository(
            PasswordEncoder passwordEncoder,
            @Value("${app.users.demo.password}") String demoPassword) {
        this.passwordEncoder = passwordEncoder;
        seed(demoPassword);
    }

    private UserRepository(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /** Empty store for tests that want full control over fixtures. */
    public static UserRepository empty(PasswordEncoder encoder) {
        return new UserRepository(encoder);
    }

    private void seed(String demoPassword) {
        try {
            String hash = passwordEncoder.encode(demoPassword);
            save(new User("admin", hash,
                    Set.of(Role.ADMIN), Set.of(), true));
            save(new User("editor", hash,
                    Set.of(Role.EDITOR), Set.of(), true));
            save(new User("viewer", hash,
                    Set.of(Role.VIEWER), Set.of(), true));
            save(new User("disabled", hash,
                    Set.of(Role.VIEWER), Set.of(), false));
            log.info("Seeded demo users: admin, editor, viewer (enabled), "
                    + "disabled (password from app.users.demo.password)");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to seed demo users", e);
        }
    }

    public Optional<User> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(users.get(username));
    }

    public User save(User user) {
        users.put(user.getUsername(), user);
        return user;
    }
}
