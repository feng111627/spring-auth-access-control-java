package com.github.feng111627.springauthaccesscontroljava.token;

/**
 * 令牌类型。令牌头部的 typ 必须与使用场景匹配，
 * 刷新令牌不能用于访问接口，访问令牌不能用于刷新。
 */
public enum TokenType {
    ACCESS("at+jwt"),
    REFRESH("rt+jwt");

    private final String headerType;

    TokenType(String headerType) {
        this.headerType = headerType;
    }

    public String headerType() {
        return headerType;
    }

    public static TokenType fromHeader(String headerType) {
        for (TokenType type : values()) {
            if (type.headerType.equals(headerType)) {
                return type;
            }
        }
        return null;
    }
}
