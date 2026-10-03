package com.github.feng111627.springauthaccesscontroljava.security;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks revoked refresh-token ids. A refresh is rejected with
 * {@link TokenError#REVOKED} after its id has been revoked by logout.
 * Entries stay for the process lifetime; this is an in-memory deployment.
 */
@Component
public class TokenRevocationService {

    private final Set<String> revokedJtis = ConcurrentHashMap.newKeySet();

    public void revoke(String jti) {
        if (jti != null && !jti.isBlank()) {
            revokedJtis.add(jti);
        }
    }

    public boolean isRevoked(String jti) {
        return jti != null && revokedJtis.contains(jti);
    }
}
