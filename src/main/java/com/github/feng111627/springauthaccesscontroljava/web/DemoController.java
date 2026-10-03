package com.github.feng111627.springauthaccesscontroljava.web;

import com.github.feng111627.springauthaccesscontroljava.security.AuthenticatedUser;
import com.github.feng111627.springauthaccesscontroljava.security.RequireAuth;
import com.github.feng111627.springauthaccesscontroljava.security.RequirePermission;
import com.github.feng111627.springauthaccesscontroljava.security.RequireRole;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** Demo resources exercising public, authenticated, role- and permission-gated access. */
@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/public/ping")
    public Map<String, Object> ping() {
        return Map.of("status", "ok", "message", "public endpoint");
    }

    @GetMapping("/me")
    @RequireAuth
    public Map<String, Object> me(
            @RequestAttribute("authenticatedUser") AuthenticatedUser user) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", user.username());
        body.put("roles", user.roles());
        body.put("permissions", user.permissions());
        body.put("epoch", user.epoch());
        return body;
    }

    @GetMapping("/admin/stats")
    @RequireRole("ADMIN")
    public Map<String, Object> adminStats(
            @RequestAttribute("authenticatedUser") AuthenticatedUser user) {
        return Map.of("status", "ok", "viewer", user.username(), "report", "admin-stats");
    }

    @GetMapping("/articles/publish")
    @RequirePermission("article:publish")
    public Map<String, Object> publishArticle(
            @RequestAttribute("authenticatedUser") AuthenticatedUser user) {
        return Map.of("status", "ok", "publisher", user.username());
    }
}
