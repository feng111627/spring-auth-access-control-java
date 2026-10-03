package com.github.feng111627.springauthaccesscontroljava.error;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 业务异常：携带错误码与可选的可解释细节（如锁定剩余秒数）。
 */
public class ApiException extends RuntimeException {

    private final ErrorCode code;
    private final Map<String, Object> details = new LinkedHashMap<>();

    public ApiException(ErrorCode code) {
        super(code.defaultMessage());
        this.code = code;
    }

    public ApiException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public ApiException(ErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ApiException with(String key, Object value) {
        details.put(key, value);
        return this;
    }

    public ErrorCode code() {
        return code;
    }

    public Map<String, Object> details() {
        return details;
    }
}
