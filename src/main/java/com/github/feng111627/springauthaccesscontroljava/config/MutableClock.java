package com.github.feng111627.springauthaccesscontroljava.config;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 可控时钟：生产环境跟随系统 UTC，测试中可整体推进时间以验证过期语义。
 */
public class MutableClock extends Clock {

    private final ZoneId zone = ZoneId.of("UTC");
    private final AtomicReference<Instant> fixed = new AtomicReference<>();

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return fixed.get() == null ? Clock.system(zone) : Clock.fixed(fixed.get(), zone);
    }

    @Override
    public Instant instant() {
        Instant value = fixed.get();
        return value != null ? value : Instant.now(clock());
    }

    private Clock clock() {
        return Clock.system(zone);
    }

    /** 固定到某个时刻（之后不再前进，直到 advance/unfreeze）。 */
    public void freezeAt(Instant instant) {
        fixed.set(instant);
    }

    /** 从当前时刻起整体推进时间（若未冻结则先冻结在真实当前时刻）。 */
    public void advance(Duration duration) {
        fixed.updateAndGet(current -> {
            Instant base = current != null ? current : Instant.now(clock());
            return base.plus(duration);
        });
    }

    /** 恢复跟随系统时间。 */
    public void unfreeze() {
        fixed.set(null);
    }
}
