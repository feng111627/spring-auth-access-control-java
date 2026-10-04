package com.github.feng111627.springauthaccesscontroljava.web;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Extracts the logical client source (an IP-like key) used by the
 * source-dimension login throttle.
 *
 * <p>Resolution order:
 * <ol>
 *   <li>the first (left-most, original client) entry of the
 *       {@code X-Forwarded-For} header — this is what a local curl or test
 *       sets to simulate "same source" / "different sources" behind a proxy;</li>
 *   <li>{@code X-Real-IP} as a fallback convention;</li>
 *   <li>the TCP peer ({@code getRemoteAddr}).</li>
 * </ol>
 * The key is intentionally kept as a trimmed string: it only needs to be a
 * stable per-client bucket key, never a validated network address.
 */
public final class ClientSourceResolver {

    private ClientSourceResolver() {
    }

    public static String resolve(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            // Left-most entry is the originating client; subsequent entries
            // are proxies appended along the chain.
            String first = forwarded.split(",", 2)[0].trim();
            if (!first.isEmpty()) {
                return first;
            }
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        String remote = request.getRemoteAddr();
        return (remote == null || remote.isBlank()) ? "unknown" : remote.trim();
    }
}
