package com.github.feng111627.springauthaccesscontroljava.tests.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.springauthaccesscontroljava.tests.support.AbstractIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Duration;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 业务覆盖（端到端 HTTP 层）：
 * 登录成功/失败原因区分、令牌缺失/篡改/过期/类型错用、401 与 403 区分、
 * 权限与账号状态变更对已签发令牌的即时语义、登出/管理员吊销、刷新令牌轮换。
 */
class AuthFlowIntegrationTest extends AbstractIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    // ---------- 登录 ----------

    @Test
    @DisplayName("正确凭据登录：返回访问令牌+刷新令牌与有效期")
    void loginSuccess() throws Exception {
        MvcResult result = login("alice", "alice123")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresInSeconds").value(2))
                .andReturn();
        JsonNode body = readBody(result);
        org.junit.jupiter.api.Assertions.assertNotEquals(
                body.get("accessToken").asText(), body.get("refreshToken").asText());
    }

    @Test
    @DisplayName("密码错误 -> 401 BAD_CREDENTIALS")
    void loginBadPassword() throws Exception {
        login("alice", "wrong-password")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("BAD_CREDENTIALS"));
    }

    @Test
    @DisplayName("不存在用户与密码错误返回相同错误码，避免账号枚举")
    void loginUnknownUser() throws Exception {
        login("ghost", "whatever")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("BAD_CREDENTIALS"));
    }

    @Test
    @DisplayName("停用账号用正确密码登录 -> 401 ACCOUNT_DISABLED，与密码错误可区分")
    void loginDisabledAccount() throws Exception {
        login("nancy", "nancy123")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("ACCOUNT_DISABLED"));
    }

    @Test
    @DisplayName("连续 3 次密码错误后第 4 次 -> 423 ACCOUNT_LOCKED（与 BAD_CREDENTIALS 可区分）")
    void lockoutAfterFailures() throws Exception {
        for (int i = 0; i < 3; i++) {
            login("alice", "bad").andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("BAD_CREDENTIALS"));
        }
        // 即使本次给出正确密码，锁定期内也一律 ACCOUNT_LOCKED
        login("alice", "alice123")
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"))
                .andExpect(jsonPath("$.details.retryAfterSeconds").isNumber());
    }

    @Test
    @DisplayName("不同来源 IP 互不影响：alice 被锁不影响 bob 正常登录")
    void lockoutScopedByAccount() throws Exception {
        for (int i = 0; i < 3; i++) {
            loginAs("alice", "bad", "10.0.0.1").andExpect(status().isUnauthorized());
        }
        loginAs("alice", "alice123", "10.0.0.1")
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
        loginAs("bob", "bob123", "10.0.0.2").andExpect(status().isOk());
    }

    @Test
    @DisplayName("请求体缺字段 -> 400 INVALID_REQUEST")
    void invalidLoginRequest() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    // ---------- 认证：令牌异常原因可区分 ----------

    @Test
    @DisplayName("无令牌访问受保护接口 -> 401 MISSING_TOKEN")
    void missingToken() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("MISSING_TOKEN"));
    }

    @Test
    @DisplayName("Authorization 方案错误 -> 401 MALFORMED_TOKEN")
    void wrongScheme() throws Exception {
        mockMvc.perform(get("/api/me").header("Authorization", "Basic abc"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("MALFORMED_TOKEN"));
    }

    @Test
    @DisplayName("结构非法的令牌 -> 401 MALFORMED_TOKEN")
    void malformedToken() throws Exception {
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("MALFORMED_TOKEN"));
    }

    @Test
    @DisplayName("签名段被篡改 -> 401 BAD_TOKEN_SIGNATURE")
    void tamperedSignature() throws Exception {
        String token = accessToken("alice", "alice123");
        String flipped = token + "B"; // 确定性地改变签名段
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + flipped))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("BAD_TOKEN_SIGNATURE"));
    }

    @Test
    @DisplayName("载荷被篡改（sub 改成 admin） -> 401 BAD_TOKEN_SIGNATURE")
    void tamperedPayload() throws Exception {
        String token = accessToken("alice", "alice123");
        String[] parts = token.split("\\.", -1);
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        String changed = payload.replace("alice", "admin");
        parts[1] = Base64.getUrlEncoder().withoutPadding().encodeToString(changed.getBytes());
        String forged = parts[0] + "." + parts[1] + "." + parts[2];
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + forged))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("BAD_TOKEN_SIGNATURE"));
    }

    @Test
    @DisplayName("用刷新令牌访问接口 -> 401 WRONG_TOKEN_TYPE")
    void wrongTokenTypeOnAccess() throws Exception {
        Tokens tokens = loginPair("alice", "alice123");
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + tokens.refresh()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("WRONG_TOKEN_TYPE"));
    }

    @Test
    @DisplayName("访问令牌过期 -> 401 TOKEN_EXPIRED，与篡改错误可区分")
    void expiredAccessToken() throws Exception {
        String token = accessToken("alice", "alice123");
        clock.advance(Duration.ofSeconds(3));
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_EXPIRED"));
    }

    // ---------- 授权：已认证但权限不足 ----------

    @Test
    @DisplayName("已认证访问 /api/me 成功并返回实时用户视图")
    void authenticatedMe() throws Exception {
        String token = accessToken("alice", "alice123");
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.roles[0]").value("USER"));
    }

    @Test
    @DisplayName("bob 缺 ADMIN 角色访问管理接口 -> 403 ACCESS_DENIED（已认证，非 401）")
    void roleForbidden() throws Exception {
        String token = accessToken("bob", "bob123");
        mockMvc.perform(get("/api/admin/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test
    @DisplayName("bob 缺 report:read 权限 -> 403；alice 有权限 -> 200")
    void permissionChecks() throws Exception {
        mockMvc.perform(get("/api/reports/view")
                        .header("Authorization", "Bearer " + accessToken("bob", "bob123")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
        mockMvc.perform(get("/api/reports/view")
                        .header("Authorization", "Bearer " + accessToken("alice", "alice123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("admin 角色可访问管理接口")
    void adminAllowed() throws Exception {
        mockMvc.perform(get("/api/admin/ping")
                        .header("Authorization", "Bearer " + accessToken("admin", "admin123")))
                .andExpect(status().isOk());
    }

    // ---------- 已签发令牌在账号变更后的语义 ----------

    @Test
    @DisplayName("权限提升对已签发令牌即时生效：bob 原被拒，授予 report:read 后同一令牌即 200")
    void permissionChangeImmediateEffect() throws Exception {
        String token = accessToken("admin", "admin123");
        String bobToken = accessToken("bob", "bob123");
        mockMvc.perform(get("/api/reports/view").header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/admin/users/bob/permissions")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"permissions\":[\"report:read\"]}"))
                .andExpect(status().isOk());

        // 不重新登录、不换令牌：下次请求立即按新权限判定
        mockMvc.perform(get("/api/reports/view").header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("管理员停用用户后，其已签发令牌下次请求 -> 401 ACCOUNT_DISABLED")
    void disableTakesEffectImmediately() throws Exception {
        String adminToken = accessToken("admin", "admin123");
        String aliceToken = accessToken("alice", "alice123");
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/admin/users/alice/disable")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("ACCOUNT_DISABLED"));
    }

    @Test
    @DisplayName("管理员强制下线后，旧令牌 -> 401 TOKEN_REVOKED")
    void adminRevokeTokens() throws Exception {
        String adminToken = accessToken("admin", "admin123");
        String bobToken = accessToken("bob", "bob123");
        mockMvc.perform(post("/api/admin/users/bob/revoke-tokens")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenVersion").value(1));

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_REVOKED"));
    }

    @Test
    @DisplayName("登出后该用户所有已签发令牌立即失效 -> TOKEN_REVOKED")
    void logoutRevokesTokens() throws Exception {
        Tokens tokens = loginPair("bob", "bob123");
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + tokens.access()))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + tokens.access()))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + tokens.access()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_REVOKED"));
        // 刷新令牌同时失效
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + tokens.refresh() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_REVOKED"));
    }

    // ---------- 刷新 ----------

    @Test
    @DisplayName("刷新成功：新令牌对可用，旧访问令牌与旧刷新令牌均失效（轮换）")
    void refreshRotation() throws Exception {
        Tokens tokens = loginPair("alice", "alice123");
        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + tokens.refresh() + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        Tokens next = parseTokens(refreshResult);

        // 新访问令牌可用
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + next.access()))
                .andExpect(status().isOk());
        // 旧访问令牌因版本递增被吊销
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + tokens.access()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_REVOKED"));
        // 旧刷新令牌不能再用
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + tokens.refresh() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_REVOKED"));
    }

    @Test
    @DisplayName("拿访问令牌调刷新接口 -> WRONG_TOKEN_TYPE")
    void accessTokenOnRefreshEndpoint() throws Exception {
        String access = accessToken("alice", "alice123");
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + access + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("WRONG_TOKEN_TYPE"));
    }

    @Test
    @DisplayName("过期的刷新令牌 -> TOKEN_EXPIRED")
    void expiredRefreshToken() throws Exception {
        Tokens tokens = loginPair("alice", "alice123");
        clock.advance(Duration.ofSeconds(6));
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + tokens.refresh() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_EXPIRED"));
    }

    @Test
    @DisplayName("篡改的刷新令牌 -> BAD_TOKEN_SIGNATURE")
    void tamperedRefreshToken() throws Exception {
        Tokens tokens = loginPair("alice", "alice123");
        String refresh = tokens.refresh();
        String flipped = refresh + "B"; // 确定性地改变签名段
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + flipped + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("BAD_TOKEN_SIGNATURE"));
    }

    // ---------- helpers ----------

    private org.springframework.test.web.servlet.ResultActions login(String username, String password)
            throws Exception {
        return loginAs(username, password, null);
    }

    private org.springframework.test.web.servlet.ResultActions loginAs(String username, String password,
                                                                      String forwardedFor)
            throws Exception {
        var request = post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}");
        if (forwardedFor != null) {
            request.header("X-Forwarded-For", forwardedFor);
        }
        return mockMvc.perform(request);
    }

    private String accessToken(String username, String password) throws Exception {
        return parseTokens(login(username, password).andReturn()).access();
    }

    private Tokens loginPair(String username, String password) throws Exception {
        return parseTokens(login(username, password).andReturn());
    }

    private Tokens parseTokens(MvcResult result) throws Exception {
        JsonNode body = readBody(result);
        return new Tokens(body.get("accessToken").asText(), body.get("refreshToken").asText());
    }

    private JsonNode readBody(MvcResult result) throws Exception {
        return JSON.readTree(result.getResponse().getContentAsString());
    }

    private record Tokens(String access, String refresh) {
    }
}
