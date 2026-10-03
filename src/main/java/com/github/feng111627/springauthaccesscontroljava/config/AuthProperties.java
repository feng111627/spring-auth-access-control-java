package com.github.feng111627.springauthaccesscontroljava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * 认证相关配置（前缀 auth.*）。
 */
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    /** HMAC 签名密钥（本地演示默认值，生产须通过环境变量覆盖）。 */
    private String hmacSecret = "local-dev-secret-please-change-0123456789";

    /** 访问令牌有效期。 */
    private Duration accessTokenTtl = Duration.ofMinutes(15);

    /** 刷新令牌有效期。 */
    private Duration refreshTokenTtl = Duration.ofHours(12);

    /** 连续登录失败多少次后锁定账号。 */
    private int maxLoginFailures = 5;

    /** 账号锁定时长。 */
    private Duration lockDuration = Duration.ofMinutes(5);

    /** 同一来源 IP 在滑动窗口内允许的失败次数。 */
    private int ipMaxFailures = 20;

    /** IP 失败计数滑动窗口长度。 */
    private Duration ipWindow = Duration.ofMinutes(10);

    public String getHmacSecret() { return hmacSecret; }
    public void setHmacSecret(String hmacSecret) { this.hmacSecret = hmacSecret; }

    public Duration getAccessTokenTtl() { return accessTokenTtl; }
    public void setAccessTokenTtl(Duration accessTokenTtl) { this.accessTokenTtl = accessTokenTtl; }

    public Duration getRefreshTokenTtl() { return refreshTokenTtl; }
    public void setRefreshTokenTtl(Duration refreshTokenTtl) { this.refreshTokenTtl = refreshTokenTtl; }

    public int getMaxLoginFailures() { return maxLoginFailures; }
    public void setMaxLoginFailures(int maxLoginFailures) { this.maxLoginFailures = maxLoginFailures; }

    public Duration getLockDuration() { return lockDuration; }
    public void setLockDuration(Duration lockDuration) { this.lockDuration = lockDuration; }

    public int getIpMaxFailures() { return ipMaxFailures; }
    public void setIpMaxFailures(int ipMaxFailures) { this.ipMaxFailures = ipMaxFailures; }

    public Duration getIpWindow() { return ipWindow; }
    public void setIpWindow(Duration ipWindow) { this.ipWindow = ipWindow; }
}
