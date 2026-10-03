package com.github.feng111627.springauthaccesscontroljava.auth;

import com.github.feng111627.springauthaccesscontroljava.user.User;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * 权限判定：实时读取用户当前的角色/权限集合，不依赖令牌内容。
 * 因此管理员调整角色/权限后，下一个请求立即按新集合判定，前后一致。
 */
@Service
public class AuthorizationService {

    public boolean hasAnyRole(User user, String... roles) {
        if (user == null || roles == null || roles.length == 0) {
            return false;
        }
        Set<String> granted = user.getRoles();
        for (String role : roles) {
            if (granted.contains(role)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasAnyPermission(User user, String... permissions) {
        if (user == null || permissions == null || permissions.length == 0) {
            return false;
        }
        Set<String> granted = user.getPermissions();
        for (String permission : permissions) {
            if (granted.contains(permission)) {
                return true;
            }
        }
        return false;
    }
}
