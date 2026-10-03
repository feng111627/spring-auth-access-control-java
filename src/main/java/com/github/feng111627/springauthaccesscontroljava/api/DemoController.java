package com.github.feng111627.springauthaccesscontroljava.api;

import com.github.feng111627.springauthaccesscontroljava.auth.AuthContext;
import com.github.feng111627.springauthaccesscontroljava.auth.RequirePermission;
import com.github.feng111627.springauthaccesscontroljava.auth.RequireRole;
import com.github.feng111627.springauthaccesscontroljava.user.UserView;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 演示接口，覆盖访问控制四档：
 * <ul>
 *   <li>GET /api/public/hello  公开</li>
 *   <li>GET /api/me            仅认证</li>
 *   <li>GET /api/admin/ping    需要 ADMIN 角色（403 场景）</li>
 *   <li>GET /api/reports/view  需要 report:read 权限（403 场景）</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/public/hello")
    public Map<String, Object> publicHello() {
        return Map.of("status", "ok", "message", "公开接口，无需令牌");
    }

    @GetMapping("/me")
    public UserView me() {
        return UserView.of(AuthContext.get());
    }

    @GetMapping("/admin/ping")
    @RequireRole("ADMIN")
    public Map<String, Object> adminPing() {
        return Map.of("status", "ok", "message", "ADMIN 角色访问成功",
                "user", AuthContext.get().getUsername());
    }

    @GetMapping("/reports/view")
    @RequirePermission("report:read")
    public Map<String, Object> reportView() {
        return Map.of("status", "ok", "message", "report:read 权限访问成功",
                "user", AuthContext.get().getUsername());
    }
}
