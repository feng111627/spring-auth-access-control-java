package com.github.feng111627.springauthaccesscontroljava.http;

import com.github.feng111627.springauthaccesscontroljava.auth.AuthContext;
import com.github.feng111627.springauthaccesscontroljava.auth.AuthorizationService;
import com.github.feng111627.springauthaccesscontroljava.auth.RequirePermission;
import com.github.feng111627.springauthaccesscontroljava.auth.RequireRole;
import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 授权拦截器：读取方法/类上的 @RequireRole、@RequirePermission 实时判定。
 * 在认证拦截器之后执行：未认证请求已被拦截为 401，到达这里一律是“已认证”，
 * 判定不通过统一抛 ACCESS_DENIED(403)，与 401 明确区分。
 * 多个角色/权限之间为 OR；同时标注两类注解时为 AND。
 */
@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private final AuthorizationService authorization;

    public AuthorizationInterceptor(AuthorizationService authorization) {
        this.authorization = authorization;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        User user = AuthContext.get();
        if (user == null) {
            // 理论不可达：认证拦截器先执行。保留以防配置遗漏。
            throw new ApiException(ErrorCode.MISSING_TOKEN, "请求尚未认证");
        }

        RequireRole roleRequirement = findAnnotation(handlerMethod, RequireRole.class);
        if (roleRequirement != null && !authorization.hasAnyRole(user, roleRequirement.value())) {
            throw new ApiException(ErrorCode.ACCESS_DENIED, "缺少所需角色之一")
                    .with("requiredAnyRole", roleRequirement.value())
                    .with("userRoles", user.getRoles());
        }

        RequirePermission permissionRequirement = findAnnotation(handlerMethod, RequirePermission.class);
        if (permissionRequirement != null
                && !authorization.hasAnyPermission(user, permissionRequirement.value())) {
            throw new ApiException(ErrorCode.ACCESS_DENIED, "缺少所需权限之一")
                    .with("requiredAnyPermission", permissionRequirement.value())
                    .with("userPermissions", user.getPermissions());
        }
        return true;
    }

    private <A extends java.lang.annotation.Annotation> A findAnnotation(HandlerMethod method, Class<A> type) {
        A onMethod = AnnotatedElementUtils.findMergedAnnotation(method.getMethod(), type);
        return onMethod != null ? onMethod : AnnotatedElementUtils.findMergedAnnotation(method.getBeanType(), type);
    }
}
