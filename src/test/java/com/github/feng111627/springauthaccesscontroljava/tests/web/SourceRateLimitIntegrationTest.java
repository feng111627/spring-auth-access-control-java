package com.github.feng111627.springauthaccesscontroljava.tests.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.springauthaccesscontroljava.security.PasswordEncoder;
import com.github.feng111627.springauthaccesscontroljava.user.Role;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end checks of the source-dimension throttle over HTTP. The logical
 * source is chosen via the {@code X-Forwarded-For} header, which is exactly
 * how "same source" vs "different sources" is simulated locally without any
 * network change. All sources/usernames here are throwaway values so the
 * shared application context is never polluted for other test classes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SourceRateLimitIntegrationTest {

    /** Keep in sync with app.login.max-source-failures. */
    private static final int MAX_SOURCE_FAILURES = 20;
    private static final ObjectMapper JSON = new ObjectMapper();

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    @Autowired
    UserRepository users;

    @Autowired
    PasswordEncoder encoder;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private ResponseEntity<String> login(String source, String username,
                                         String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (source != null) {
            headers.set("X-Forwarded-For", source);
        }
        return rest.postForEntity(url("/api/auth/login"),
                new HttpEntity<>(Map.of("username", username, "password", password),
                        headers),
                String.class);
    }

    private static String code(ResponseEntity<String> response) {
        try {
            JsonNode body = JSON.readTree(response.getBody());
            return body.get("code").asText();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("同一来源轮换用户名爆破: 前 20 次 401 LOGIN_BAD_CREDENTIALS, 第 21 次 429 LOGIN_SOURCE_RATE_LIMITED")
    void sameSourceAcrossUsernamesGetsDistinct429() {
        String source = "203.0.113.10";
        for (int i = 0; i < MAX_SOURCE_FAILURES; i++) {
            ResponseEntity<String> response =
                    login(source, "http-ghost-alpha-" + i, "x");
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode(),
                    "attempt " + i);
            assertEquals("LOGIN_BAD_CREDENTIALS", code(response));
        }

        ResponseEntity<String> blocked =
                login(source, "http-ghost-alpha-extra", "x");
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, blocked.getStatusCode());
        assertEquals("LOGIN_SOURCE_RATE_LIMITED", code(blocked));
    }

    @Test
    @DisplayName("不同来源互不影响: A 来源已 429, B 来源用同类用户名仍 401")
    void differentSourceIsNotThrottled() {
        String blockedSource = "203.0.113.20";
        for (int i = 0; i < MAX_SOURCE_FAILURES; i++) {
            assertEquals(HttpStatus.UNAUTHORIZED,
                    login(blockedSource, "http-ghost-beta-" + i, "x")
                            .getStatusCode());
        }
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,
                login(blockedSource, "http-ghost-beta-extra", "x")
                        .getStatusCode());

        // A brand new source starts with a clean bucket.
        ResponseEntity<String> fresh =
                login("203.0.113.21", "http-ghost-beta-0", "x");
        assertEquals(HttpStatus.UNAUTHORIZED, fresh.getStatusCode());
        assertEquals("LOGIN_BAD_CREDENTIALS", code(fresh));
    }

    @Test
    @DisplayName("账号维度独立可达: 同一账号每次换来源连错 5 次, 第 6 次(新来源) 423 LOGIN_ACCOUNT_LOCKED")
    void accountLockReachableFromRotatingSources() throws Exception {
        String username = "http-lock-victim";
        users.save(new User(username, encoder.encode("S3cret!correct"),
                Set.of(Role.VIEWER), Set.of(), true));

        for (int i = 0; i < 5; i++) {
            ResponseEntity<String> response =
                    login("198.51.100." + i, username, "wrong");
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("LOGIN_BAD_CREDENTIALS", code(response));
        }
        // A sixth, previously unseen source still meets the account lock;
        // its own source bucket is empty so 429 can never appear here.
        ResponseEntity<String> locked =
                login("198.51.100.200", username, "S3cret!correct");
        assertEquals(HttpStatus.LOCKED, locked.getStatusCode());
        assertEquals("LOGIN_ACCOUNT_LOCKED", code(locked));
    }

    @Test
    @DisplayName("两维同时满足: 来源 429 优先于账号 423, 且与 401 密码错三种结果可分辨")
    void source429OutranksAccount423OverHttp() throws Exception {
        String username = "http-both-victim";
        users.save(new User(username, encoder.encode("S3cret!correct"),
                Set.of(Role.VIEWER), Set.of(), true));

        // Lock the account using rotating sources (source bucket untouched).
        for (int i = 0; i < 5; i++) {
            assertEquals("LOGIN_BAD_CREDENTIALS",
                    code(login("198.51.101." + i, username, "wrong")));
        }
        // Independently fill the source bucket from one fixed source via
        // username spray (none of these names exists).
        String sprayingSource = "198.51.101.250";
        for (int i = 0; i < MAX_SOURCE_FAILURES; i++) {
            assertEquals("LOGIN_BAD_CREDENTIALS",
                    code(login(sprayingSource, "http-spray-gamma-" + i, "x")));
        }

        // Both gates active: correct password from the spraying source is
        // still 429 SOURCE_RATE_LIMITED, never 423.
        ResponseEntity<String> blocked =
                login(sprayingSource, username, "S3cret!correct");
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, blocked.getStatusCode());
        assertEquals("LOGIN_SOURCE_RATE_LIMITED", code(blocked));

        // A clean source observes the still-active account lock: the account
        // dimension was not replaced, only outranked.
        ResponseEntity<String> locked =
                login("198.51.101.251", username, "S3cret!correct");
        assertEquals(HttpStatus.LOCKED, locked.getStatusCode());
        assertEquals("LOGIN_ACCOUNT_LOCKED", code(locked));
    }
}
