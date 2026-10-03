package com.github.feng111627.springauthaccesscontroljava.login;

import com.github.feng111627.springauthaccesscontroljava.config.AuthProperties;
import com.github.feng111627.springauthaccesscontroljava.config.MutableClock;
import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录失败计数、账号短时锁定与来源 IP 限流。
 * <p>
 * 并发正确性：
 * <ul>
 *   <li>每个用户名对应一个独立的 AccountState，计数/锁定变更在该对象上同步，
 *       同一账号的并发失败不会丢失自增或互相覆盖锁定时间；</li>
 *   <li>每个来源 IP 对应一个独立的滑动窗口，窗口裁剪与计数同样在该对象上同步。</li>
 * </ul>
 * 规则（可在 application.properties 调整）：
 * <ul>
 *   <li>账号：连续失败达到 maxLoginFailures 次后锁定 lockDuration；
 *       锁定期间直接判定 ACCOUNT_LOCKED，锁过期后计数清零重新开始；</li>
 *   <li>IP：滑动窗口 ipWindow 内失败超过 ipMaxFailures 次判定 RATE_LIMITED。</li>
 * </ul>
 * 检查顺序固定为：先 IP 限流，再账号锁定，保证结果确定。
 */
@Service
public class LoginAttemptService {

    /** 登录前置检查/失败记录后的状态快照。 */
    public record GateResult(boolean locked, long retryAfterSeconds, int failureCount) {
    }

    /** 账号维度状态；所有字段只在 this 监视器内读写。 */
    private static final class AccountState {
        int failures;
        long lockedUntilEpochSecond;
    }

    /** IP 维度滑动窗口；时间戳列表只在 this 监视器内读写。 */
    private static final class IpWindow {
        final List<Long> failureTimes = new ArrayList<>();
    }

    private final AuthProperties properties;
    private final MutableClock clock;
    private final ConcurrentHashMap<String, AccountState> accountStates = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, IpWindow> ipStates = new ConcurrentHashMap<>();

    public LoginAttemptService(AuthProperties properties, MutableClock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * 凭据校验前调用。
     *
     * @throws ApiException RATE_LIMITED 或 ACCOUNT_LOCKED（带 retryAfterSeconds 细节）
     */
    public void assertLoginAllowed(String username, String clientIp) {
        long now = nowSeconds();
        String ipKey = clientIp == null ? "unknown" : clientIp;
        IpWindow window = ipStates.computeIfAbsent(ipKey, k -> new IpWindow());
        AccountState state = accountStates.computeIfAbsent(username, k -> new AccountState());

        // 与 registerCredentialFailure 保持相同的“先 IP 后账号”加锁顺序
        synchronized (window) {
            pruneWindow(window, now);
            if (window.failureTimes.size() >= properties.getIpMaxFailures()) {
                throw new ApiException(ErrorCode.RATE_LIMITED, "来源登录失败过于频繁，请稍后再试")
                        .with("retryAfterSeconds", properties.getIpWindow().getSeconds());
            }
            synchronized (state) {
                if (state.lockedUntilEpochSecond > now) {
                    throw new ApiException(ErrorCode.ACCOUNT_LOCKED, "账号已锁定，请稍后再试")
                            .with("retryAfterSeconds", state.lockedUntilEpochSecond - now)
                            .with("failureCount", state.failures);
                }
                // 锁已过期：惰性清零，开始新的一轮计数
                if (state.lockedUntilEpochSecond != 0 && state.lockedUntilEpochSecond <= now) {
                    state.failures = 0;
                    state.lockedUntilEpochSecond = 0;
                }
            }
        }
    }

    /**
     * 记录一次失败（同时计入账号与来源 IP）。
     * 达到阈值的“当次”失败仍由调用方报 BAD_CREDENTIALS，锁从下一次尝试开始生效。
     */
    public GateResult recordFailure(String username, String clientIp) {
        long now = nowSeconds();

        IpWindow window = ipStates.computeIfAbsent(clientIp == null ? "unknown" : clientIp, k -> new IpWindow());
        synchronized (window) {
            pruneWindow(window, now);
            window.failureTimes.add(now);
        }

        AccountState state = accountStates.computeIfAbsent(username, k -> new AccountState());
        synchronized (state) {
            // 若恰好在“已过期但未惰性清理”时记录失败，先清理，保证语义一致
            if (state.lockedUntilEpochSecond != 0 && state.lockedUntilEpochSecond <= now) {
                state.failures = 0;
                state.lockedUntilEpochSecond = 0;
            }
            state.failures++;
            if (state.failures >= properties.getMaxLoginFailures() && state.lockedUntilEpochSecond <= now) {
                state.lockedUntilEpochSecond = now + properties.getLockDuration().getSeconds();
            }
            boolean locked = state.lockedUntilEpochSecond > now;
            long retryAfter = locked ? state.lockedUntilEpochSecond - now : 0L;
            return new GateResult(locked, retryAfter, state.failures);
        }
    }

    /**
     * 登录失败的统一原子入口：IP 限流检查、IP 计数、账号锁定复查与账号计数
     * 以固定顺序加锁完成，杜绝“先各自通过闸门、再各自计数”的并发超记。
     * <p>
     * 成功登记一次失败后正常返回（调用方随后报 BAD_CREDENTIALS）；
     * 若命中 IP 限流或账号已锁定，则抛出对应异常且不改变计数。
     * IP 窗口与账号状态是两把独立锁，固定“先 IP 后账号”的加锁顺序以避免死锁。
     */
    public void registerCredentialFailure(String username, String clientIp) {
        long now = nowSeconds();
        String ipKey = clientIp == null ? "unknown" : clientIp;
        IpWindow window = ipStates.computeIfAbsent(ipKey, k -> new IpWindow());
        AccountState state = accountStates.computeIfAbsent(username, k -> new AccountState());

        synchronized (window) {
            pruneWindow(window, now);
            if (window.failureTimes.size() >= properties.getIpMaxFailures()) {
                throw new ApiException(ErrorCode.RATE_LIMITED, "来源登录失败过于频繁，请稍后再试")
                        .with("retryAfterSeconds", properties.getIpWindow().getSeconds());
            }
            synchronized (state) {
                if (state.lockedUntilEpochSecond > now) {
                    throw new ApiException(ErrorCode.ACCOUNT_LOCKED, "账号已锁定，请稍后再试")
                            .with("retryAfterSeconds", state.lockedUntilEpochSecond - now)
                            .with("failureCount", state.failures);
                }
                if (state.lockedUntilEpochSecond != 0 && state.lockedUntilEpochSecond <= now) {
                    state.failures = 0;
                    state.lockedUntilEpochSecond = 0;
                }
                state.failures++;
                if (state.failures >= properties.getMaxLoginFailures()) {
                    state.lockedUntilEpochSecond = now + properties.getLockDuration().getSeconds();
                }
                // 仅在确属一次新失败时计入 IP 窗口
                window.failureTimes.add(now);
            }
        }
    }

    /** 登录成功后清零该账号的失败计数与锁定（IP 窗口保留，防止借成功登录重置 IP 限流）。 */
    public void recordSuccess(String username) {
        AccountState state = accountStates.get(username);
        if (state != null) {
            synchronized (state) {
                state.failures = 0;
                state.lockedUntilEpochSecond = 0;
            }
        }
    }

    /** 仅供测试：重置全部计数。 */
    public void reset() {
        accountStates.clear();
        ipStates.clear();
    }

    private void pruneWindow(IpWindow window, long now) {
        long cutoff = now - properties.getIpWindow().getSeconds();
        window.failureTimes.removeIf(time -> time < cutoff);
    }

    long nowSeconds() {
        return clock.instant().getEpochSecond();
    }
}
