package com.github.feng111627.springauthaccesscontroljava.error;

import java.util.Map;

/**
 * 统一错误响应体。
 *
 * @param code    机器可判别的错误码
 * @param message 可解释的人类可读信息
 * @param details 附加细节（可空），例如 retryAfterSeconds
 */
public record ApiError(String code, String message, Map<String, Object> details) {
}
