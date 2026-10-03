package com.github.feng111627.springauthaccesscontroljava.web.dto;

import java.time.Instant;

/** Deterministic error body: stable code plus a human-explainable message. */
public record ErrorResponse(String code, String message, Instant timestamp) {
}
