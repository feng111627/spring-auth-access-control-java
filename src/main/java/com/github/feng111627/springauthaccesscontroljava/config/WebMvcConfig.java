package com.github.feng111627.springauthaccesscontroljava.config;

import com.github.feng111627.springauthaccesscontroljava.http.AccessTokenInterceptor;
import com.github.feng111627.springauthaccesscontroljava.http.AuthorizationInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 拦截器顺序（先认证后授权）：
 * <pre>
 *   /api/auth/login、/api/auth/refresh、/api/public/**  → 不拦截
 *   其他 /api/** → AccessTokenInterceptor → AuthorizationInterceptor
 * </pre>
 * 未携带令牌 → 401；已认证但角色/权限不足 → 403。
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    static final String[] PUBLIC_PATHS = {
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/public/**"
    };

    private final AccessTokenInterceptor accessTokenInterceptor;
    private final AuthorizationInterceptor authorizationInterceptor;

    public WebMvcConfig(AccessTokenInterceptor accessTokenInterceptor,
                        AuthorizationInterceptor authorizationInterceptor) {
        this.accessTokenInterceptor = accessTokenInterceptor;
        this.authorizationInterceptor = authorizationInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(accessTokenInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns(PUBLIC_PATHS)
                .order(0);
        registry.addInterceptor(authorizationInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns(PUBLIC_PATHS)
                .order(1);
    }
}
