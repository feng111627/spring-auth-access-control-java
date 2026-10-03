package com.github.feng111627.springauthaccesscontroljava.auth;

import com.github.feng111627.springauthaccesscontroljava.security.AccessDeniedException;
import com.github.feng111627.springauthaccesscontroljava.security.AuthenticatedUser;
import com.github.feng111627.springauthaccesscontroljava.security.RequireAuth;
import com.github.feng111627.springauthaccesscontroljava.security.RequirePermission;
import com.github.feng111627.springauthaccesscontroljava.security.RequireRole;
import com.github.feng111627.springauthaccesscontroljava.security.TokenError;
import com.github.feng111627.springauthaccesscontroljava.security.TokenException;
import com.github.feng111627.springauthaccesscontroljava.security.TokenPayload;
import com.github.feng111627.springauthaccesscontroljava.security.TokenRevocationService;
import com.github.feng111627.springauthaccesscontroljava.security.TokenService;
import com.github.feng111627.springauthaccesscontroljava.security.TokenType;
import com.github.feng111627.springauthaccesscontroljava.user.Role;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Authenticates Bearer access tokens and enforces {@link RequireRole} /
 * {@link RequirePermission} on handler methods (or types).
 *
 * <p>Outcome split:
 * <ul>
 *   <li>missing/malformed/tampered/expired/wrong-type token &rarr;
 *       {@link TokenException} &rarr; HTTP 401 (unauthenticated);</li>
 *   <li>valid token but stale epoch / disabled account &rarr;
 *       {@link TokenException} &rarr; HTTP 401 as well, because the presented
 *       credential can no longer establish an identity;</li>
 *   <li>established identity lacking a role/permission &rarr;
 *       {@link AccessDeniedException} &rarr; HTTP 403 (forbidden).</li>
 * </ul>
 *
 * Roles/permissions/enabled/epoch are always read live from
 * {@link UserRepository}, never trusted from the token.
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    public static final String PRINCIPAL_ATTRIBUTE = "authenticatedUser";
    private static final String BEARER_PREFIX = "Bearer ";

    private final TokenService tokenService;
    private final TokenRevocationService revocationService;
    private final UserRepository userRepository;

    public AuthInterceptor(TokenService tokenService,
                           TokenRevocationService revocationService,
                           UserRepository userRepository) {
        this.tokenService = tokenService;
        this.revocationService = revocationService;
        this.userRepository = userRepository;
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        // Method-level annotations take precedence; fall back to type-level.
        RequireRole roleRequirement = firstPresent(
                handlerMethod.getMethodAnnotation(RequireRole.class),
                handlerMethod.getBeanType().getAnnotation(RequireRole.class));
        RequirePermission permissionRequirement = firstPresent(
                handlerMethod.getMethodAnnotation(RequirePermission.class),
                handlerMethod.getBeanType().getAnnotation(RequirePermission.class));
        RequireAuth authRequirement = firstPresent(
                handlerMethod.getMethodAnnotation(RequireAuth.class),
                handlerMethod.getBeanType().getAnnotation(RequireAuth.class));

        // No guard annotations => endpoint is intentionally public.
        if (roleRequirement == null && permissionRequirement == null
                && authRequirement == null) {
            return true;
        }

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)
                || header.length() == BEARER_PREFIX.length()) {
            throw new TokenException(TokenError.MALFORMED);
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();

        // A refresh token on a protected API is exactly the WRONG_TYPE case.
        TokenPayload payload = tokenService.verify(token, TokenType.ACCESS);

        User user = userRepository.findByUsername(payload.subject()).orElse(null);
        if (user == null) {
            throw new TokenException(TokenError.REVOKED);
        }
        // Live account state is checked first: a disabled account is reported
        // as USER_DISABLED even if its token also predates an epoch change.
        if (!user.isEnabled()) {
            throw new TokenException(TokenError.USER_DISABLED);
        }
        if (payload.epoch() != user.getTokenEpoch()) {
            throw new TokenException(TokenError.STALE_EPOCH);
        }

        Set<String> roleNames = user.getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.toUnmodifiableSet());
        Set<String> livePermissions = effectivePermissions(user);

        AuthenticatedUser principal = new AuthenticatedUser(
                user.getUsername(), roleNames, livePermissions, user.getTokenEpoch());
        request.setAttribute(PRINCIPAL_ATTRIBUTE, principal);

        enforceRole(roleRequirement, roleNames);
        enforcePermission(permissionRequirement, livePermissions);
        return true;
    }

    private Set<String> effectivePermissions(User user) {
        Set<String> all = new HashSet<>(user.getPermissions());
        for (Role role : user.getRoles()) {
            all.addAll(role.permissions());
        }
        return Set.copyOf(all);
    }

    private void enforceRole(RequireRole requirement, Set<String> roleNames) {
        if (requirement != null && !roleNames.contains(requirement.value())) {
            throw new AccessDeniedException("role " + requirement.value());
        }
    }

    private void enforcePermission(RequirePermission requirement,
                                   Set<String> permissions) {
        if (requirement != null && !permissions.contains(requirement.value())) {
            throw new AccessDeniedException("permission " + requirement.value());
        }
    }

    @SafeVarargs
    private static <T> T firstPresent(T... values) {
        for (T value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }
}
