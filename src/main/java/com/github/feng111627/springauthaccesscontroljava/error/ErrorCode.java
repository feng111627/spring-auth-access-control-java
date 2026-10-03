package com.github.feng111627.springauthaccesscontroljava.error;

import org.springframework.http.HttpStatus;

/**
 * 全局错误码。每一种业务失败都有独立、可区分的错误码，
 * 响应体统一为 {code, message, details}（见 ApiError）。
 */
public enum ErrorCode {
    // 认证前置：请求本身的问题
    MISSING_TOKEN(HttpStatus.UNAUTHORIZED, "缺少访问令牌"),
    MALFORMED_TOKEN(HttpStatus.UNAUTHORIZED, "令牌格式非法"),
    UNSUPPORTED_TOKEN(HttpStatus.UNAUTHORIZED, "令牌类型不被支持"),
    BAD_TOKEN_SIGNATURE(HttpStatus.UNAUTHORIZED, "令牌签名无效（令牌可能被篡改）"),
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "令牌已过期"),
    WRONG_TOKEN_TYPE(HttpStatus.UNAUTHORIZED, "令牌类型错误（访问接口须使用访问令牌）"),
    TOKEN_REVOKED(HttpStatus.UNAUTHORIZED, "令牌已被吊销"),
    ACCOUNT_DISABLED(HttpStatus.UNAUTHORIZED, "账号已被停用"),

    // 认证 / 授权结果
    BAD_CREDENTIALS(HttpStatus.UNAUTHORIZED, "用户名或密码错误"),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "已认证但权限不足"),

    // 登录防护
    ACCOUNT_LOCKED(HttpStatus.LOCKED, "账号因多次登录失败被短时锁定"),
    RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "登录请求过于频繁，已触发限流"),

    // 用户管理
    USER_ALREADY_EXISTS(HttpStatus.CONFLICT, "用户名已存在"),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "用户不存在"),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "请求参数不合法"),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "服务器内部错误");

    private final HttpStatus httpStatus;
    private final String defaultMessage;

    ErrorCode(HttpStatus httpStatus, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}
