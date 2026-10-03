package com.github.feng111627.springauthaccesscontroljava.tests.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Covers access-control distinctions end to end:
 * anonymous access (401), authenticated-but-unauthorized (403), role gates
 * and fine-grained permission gates, plus a public endpoint.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AccessControlIntegrationTest {

    private static final String PASSWORD = "Passw0rd!";
    private static final ObjectMapper JSON = new ObjectMapper();

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private String accessToken(String username) {
        ResponseEntity<String> login = rest.postForEntity(url("/api/auth/login"),
                Map.of("username", username, "password", PASSWORD), String.class);
        assertEquals(HttpStatus.OK, login.getStatusCode(), login.getBody());
        try {
            return JSON.readTree(login.getBody()).get("accessToken").asText();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ResponseEntity<String> get(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(url(path), HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
    }

    private static String code(ResponseEntity<String> response) throws Exception {
        JsonNode node = JSON.readTree(response.getBody());
        return node.get("code").asText();
    }

    @Test
    @DisplayName("公开接口无需令牌即可访问")
    void publicEndpointIsOpen() {
        ResponseEntity<String> response = get("/api/public/ping", null);
        assertEquals(HttpStatus.OK, response.getStatusCode(), response.getBody());
    }

    @Nested
    @DisplayName("未认证 (401) 与权限不足 (403) 必须区分")
    class UnauthenticatedVsForbidden {

        @Test
        @DisplayName("匿名访问角色接口 -> 401 而非 403")
        void anonymousRoleEndpointIs401() throws Exception {
            ResponseEntity<String> response = get("/api/admin/stats", null);
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("TOKEN_MALFORMED", code(response));
        }

        @Test
        @DisplayName("匿名访问权限接口 -> 401 而非 403")
        void anonymousPermissionEndpointIs401() throws Exception {
            ResponseEntity<String> response = get("/api/articles/publish", null);
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
            assertEquals("TOKEN_MALFORMED", code(response));
        }

        @Test
        @DisplayName("已认证但角色不足 -> 403 ACCESS_DENIED")
        void wrongRoleIs403() throws Exception {
            String viewerToken = accessToken("viewer");
            ResponseEntity<String> response = get("/api/admin/stats", viewerToken);
            assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode(),
                    response.getBody());
            assertEquals("ACCESS_DENIED", code(response));
        }

        @Test
        @DisplayName("已认证但权限不足 -> 403 ACCESS_DENIED")
        void missingPermissionIs403() throws Exception {
            String viewerToken = accessToken("viewer");
            ResponseEntity<String> response =
                    get("/api/articles/publish", viewerToken);
            assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
            assertEquals("ACCESS_DENIED", code(response));
        }
    }

    @Nested
    @DisplayName("角色与权限模型")
    class RoleAndPermissionModel {

        @Test
        @DisplayName("ADMIN 可访问角色受限的 admin 接口")
        void adminReachesAdminEndpoint() {
            String adminToken = accessToken("admin");
            ResponseEntity<String> response = get("/api/admin/stats", adminToken);
            assertEquals(HttpStatus.OK, response.getStatusCode(), response.getBody());
        }

        @Test
        @DisplayName("EDITOR 凭借角色映射的 article:publish 权限可发文")
        void editorReachesPermissionEndpoint() {
            String editorToken = accessToken("editor");
            ResponseEntity<String> response =
                    get("/api/articles/publish", editorToken);
            assertEquals(HttpStatus.OK, response.getStatusCode(), response.getBody());
        }

        @Test
        @DisplayName("ADMIN 凭借角色权限同样可发文 (权限并集)")
        void adminReachesPermissionEndpoint() {
            String adminToken = accessToken("admin");
            ResponseEntity<String> response =
                    get("/api/articles/publish", adminToken);
            assertEquals(HttpStatus.OK, response.getStatusCode(), response.getBody());
        }

        @Test
        @DisplayName("VIEWER 有 article:read, 但没有任何读接口要求它; 403 信息指出所缺要求")
        void forbiddenMessageNamesRequirement() throws Exception {
            String viewerToken = accessToken("viewer");
            ResponseEntity<String> response = get("/api/admin/stats", viewerToken);
            JsonNode body = JSON.readTree(response.getBody());
            assertEquals("ACCESS_DENIED", body.get("code").asText());
            assertEquals(true, body.get("message").asText().contains("role ADMIN"));
        }

        @Test
        @DisplayName("仅认证即可的接口, 任意有效用户可访问")
        void anyAuthenticatedUserHitsMe() {
            String viewerToken = accessToken("viewer");
            ResponseEntity<String> response = get("/api/me", viewerToken);
            assertEquals(HttpStatus.OK, response.getStatusCode(), response.getBody());
        }
    }
}
