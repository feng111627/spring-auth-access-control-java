package com.github.feng111627.springauthaccesscontroljava.tests.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.springauthaccesscontroljava.user.Role;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Base64;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end HTTP flows for login, token lifecycle and the distinguishable
 * error codes returned over the wire. Runs on a random local port.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthFlowIntegrationTest {

    private static final String PASSWORD = "Passw0rd!";
    private static final ObjectMapper JSON = new ObjectMapper();

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    @Autowired
    UserRepository users;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private ResponseEntity<String> post(String path, Object body) {
        return rest.postForEntity(url(path), body, String.class);
    }

    private JsonNode loginAs(String username) {
        ResponseEntity<String> response = post("/api/auth/login",
                Map.of("username", username, "password", PASSWORD));
        assertEquals(HttpStatus.OK, response.getStatusCode(), response.getBody());
        return readBody(response);
    }

    private static JsonNode readBody(ResponseEntity<String> response) {
        try {
            return JSON.readTree(response.getBody());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ResponseEntity<String> getWithBearer(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(url(path), HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
    }

    private static JsonNode errorBody(ResponseEntity<String> response) {
        return readBody(response);
    }

    @Nested
    @DisplayName("登录与受保护资源")
    class LoginAndAccess {

        @Test
        @DisplayName("正确密码登录成功并返回 Bearer 令牌对及有效期")
        void loginSucceeds() {
            JsonNode tokens = loginAs("viewer");
            assertTrue(tokens.get("accessToken").asText().contains("."));
            assertTrue(tokens.get("refreshToken").asText().contains("."));
            assertEquals("Bearer", tokens.get("tokenType").asText());
            assertTrue(tokens.get("accessTokenExpiresInMillis").asLong() > 0);
        }

        @Test
        @DisplayName("错误密码 -> 401 LOGIN_BAD_CREDENTIALS")
        void wrongPasswordIs401WithDistinctCode() {
            ResponseEntity<String> response = post("/api/auth/login",
                    Map.of("username", "viewer", "password", "totally-wrong"));
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("LOGIN_BAD_CREDENTIALS",
                    errorBody(response).get("code").asText());
        }

        @Test
        @DisplayName("禁用账号用正确密码 -> 401 LOGIN_ACCOUNT_DISABLED")
        void disabledUserGetsDistinctCode() {
            ResponseEntity<String> response = post("/api/auth/login",
                    Map.of("username", "disabled", "password", PASSWORD));
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("LOGIN_ACCOUNT_DISABLED",
                    errorBody(response).get("code").asText());
        }

        @Test
        @DisplayName("携带 access token 访问 /api/me 返回实时身份信息")
        void accessTokenReachesProtectedEndpoint() {
            JsonNode tokens = loginAs("editor");
            ResponseEntity<String> response =
                    getWithBearer("/api/me", tokens.get("accessToken").asText());
            assertEquals(HttpStatus.OK, response.getStatusCode(), response.getBody());
            JsonNode me = readBody(response);
            assertEquals("editor", me.get("username").asText());
            assertTrue(me.get("roles").toString().contains("EDITOR"));
            assertTrue(me.get("permissions").toString().contains("article:publish"));
        }
    }

    @Nested
    @DisplayName("令牌异常必须可区分 (HTTP)")
    class TokenFailuresOverHttp {

        @Test
        @DisplayName("无令牌访问受保护接口 -> 401 TOKEN_MALFORMED")
        void missingTokenIs401() {
            ResponseEntity<String> response = getWithBearer("/api/me", null);
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("TOKEN_MALFORMED", errorBody(response).get("code").asText());
        }

        @Test
        @DisplayName("篡改 payload 的 access token -> 401 TOKEN_SIGNATURE_INVALID")
        void tamperedTokenIs401SignatureInvalid() {
            JsonNode tokens = loginAs("viewer");
            String token = tokens.get("accessToken").asText();
            String[] parts = token.split("\\.");
            String forgedBody = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"sub\":\"admin\"}".getBytes());
            String forged = parts[0] + "." + forgedBody + "." + parts[2];

            ResponseEntity<String> response = getWithBearer("/api/me", forged);
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("TOKEN_SIGNATURE_INVALID",
                    errorBody(response).get("code").asText());
        }

        @Test
        @DisplayName("把 refresh token 用于受保护接口 -> 401 TOKEN_WRONG_TYPE")
        void refreshTokenOnApiIsWrongType() {
            JsonNode tokens = loginAs("viewer");
            ResponseEntity<String> response =
                    getWithBearer("/api/me", tokens.get("refreshToken").asText());
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("TOKEN_WRONG_TYPE", errorBody(response).get("code").asText());
        }

        @Test
        @DisplayName("垃圾字符串令牌 -> 401 TOKEN_MALFORMED")
        void garbageTokenIsMalformed() {
            ResponseEntity<String> response = getWithBearer("/api/me", "not-a-token");
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("TOKEN_MALFORMED", errorBody(response).get("code").asText());
        }
    }

    @Nested
    @DisplayName("刷新轮换与登出吊销")
    class RefreshRotationAndRevocation {

        @Test
        @DisplayName("refresh 轮换新令牌, 旧 refresh 再用 -> 401 TOKEN_REVOKED")
        void refreshRotatesAndOldRefreshIsRevoked() {
            JsonNode first = loginAs("viewer");
            String oldRefresh = first.get("refreshToken").asText();

            ResponseEntity<String> refreshResponse = post("/api/auth/refresh",
                    Map.of("refreshToken", oldRefresh));
            assertEquals(HttpStatus.OK, refreshResponse.getStatusCode(),
                    refreshResponse.getBody());
            JsonNode second = readBody(refreshResponse);
            assertNotEquals(oldRefresh, second.get("refreshToken").asText());

            // Replay the rotated-out refresh token.
            ResponseEntity<String> replay = post("/api/auth/refresh",
                    Map.of("refreshToken", oldRefresh));
            assertEquals(HttpStatus.UNAUTHORIZED, replay.getStatusCode());
            assertEquals("TOKEN_REVOKED", errorBody(replay).get("code").asText());
        }

        @Test
        @DisplayName("登出后 refresh token 立即吊销")
        void logoutRevokesRefreshToken() {
            JsonNode tokens = loginAs("viewer");
            String refresh = tokens.get("refreshToken").asText();

            ResponseEntity<Void> logout = rest.exchange(url("/api/auth/logout"),
                    org.springframework.http.HttpMethod.POST,
                    new HttpEntity<>(Map.of("refreshToken", refresh)), Void.class);
            assertEquals(HttpStatus.NO_CONTENT, logout.getStatusCode());

            ResponseEntity<String> after = post("/api/auth/refresh",
                    Map.of("refreshToken", refresh));
            assertEquals(HttpStatus.UNAUTHORIZED, after.getStatusCode());
            assertEquals("TOKEN_REVOKED", errorBody(after).get("code").asText());
        }

        @Test
        @DisplayName("把 access token 提交给刷新接口 -> 401 TOKEN_WRONG_TYPE")
        void accessTokenOnRefreshEndpointIsWrongType() {
            JsonNode tokens = loginAs("viewer");
            ResponseEntity<String> response = post("/api/auth/refresh",
                    Map.of("refreshToken", tokens.get("accessToken").asText()));
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("TOKEN_WRONG_TYPE", errorBody(response).get("code").asText());
        }
    }

    @Nested
    @DisplayName("账号变化后已签发令牌的生效语义")
    class EpochSemantics {

        @Test
        @DisplayName("权限被修改后, 旧 access token 立即失效 -> 401 TOKEN_STALE_EPOCH, 重新登录后恢复")
        void changingPermissionsInvalidatesOutstandingTokens() {
            JsonNode tokens = loginAs("viewer");
            String access = tokens.get("accessToken").asText();
            assertEquals(HttpStatus.OK, getWithBearer("/api/me", access).getStatusCode());

            User viewer = users.findByUsername("viewer").orElseThrow();
            viewer.setPermissions(Set.of("article:read", "newly:granted"));

            ResponseEntity<String> stale = getWithBearer("/api/me", access);
            assertEquals(HttpStatus.UNAUTHORIZED, stale.getStatusCode());
            assertEquals("TOKEN_STALE_EPOCH", errorBody(stale).get("code").asText());

            // Re-login obtains tokens at the new epoch.
            JsonNode renewed = loginAs("viewer");
            ResponseEntity<String> ok = getWithBearer(
                    "/api/me", renewed.get("accessToken").asText());
            assertEquals(HttpStatus.OK, ok.getStatusCode());
            assertTrue(readBody(ok).get("permissions").toString()
                    .contains("newly:granted"));

            // Restore fixture for other tests.
            users.findByUsername("viewer").orElseThrow()
                    .setPermissions(Set.of());
        }

        @Test
        @DisplayName("账号被禁用后, 其旧 access token 立即失效 -> 401 TOKEN_USER_DISABLED")
        void disablingAccountInvalidatesOutstandingTokens() {
            JsonNode tokens = loginAs("editor");
            String access = tokens.get("accessToken").asText();
            assertEquals(HttpStatus.OK, getWithBearer("/api/me", access).getStatusCode());

            User editor = users.findByUsername("editor").orElseThrow();
            editor.setEnabled(false);
            try {
                ResponseEntity<String> disabled = getWithBearer("/api/me", access);
                assertEquals(HttpStatus.UNAUTHORIZED, disabled.getStatusCode());
                assertEquals("TOKEN_USER_DISABLED",
                        errorBody(disabled).get("code").asText());
            } finally {
                editor.setEnabled(true);
            }

            // Re-enabled: the pre-disable token still carries the older epoch
            // and must remain rejected until re-login (consistent semantics).
            ResponseEntity<String> stale = getWithBearer("/api/me", access);
            assertEquals(HttpStatus.UNAUTHORIZED, stale.getStatusCode());
            assertEquals("TOKEN_STALE_EPOCH", errorBody(stale).get("code").asText());
        }

        @Test
        @DisplayName("角色变更同样推进 epoch 并即时生效")
        void roleChangeAdvancesEpoch() {
            User viewer = users.findByUsername("viewer").orElseThrow();
            long before = viewer.getTokenEpoch();
            viewer.setRoles(Set.of(Role.EDITOR));
            long after = viewer.getTokenEpoch();
            assertTrue(after > before, "epoch must advance on role change");

            // Viewer-turned-editor can now hit a permission-gated endpoint
            // after a fresh login.
            JsonNode tokens = loginAs("viewer");
            ResponseEntity<String> response = getWithBearer(
                    "/api/articles/publish", tokens.get("accessToken").asText());
            assertEquals(HttpStatus.OK, response.getStatusCode(), response.getBody());

            users.findByUsername("viewer").orElseThrow()
                    .setRoles(Set.of(Role.VIEWER));
        }
    }
}
