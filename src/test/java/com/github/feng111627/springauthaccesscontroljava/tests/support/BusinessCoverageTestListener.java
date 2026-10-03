package com.github.feng111627.springauthaccesscontroljava.tests.support;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Prints one line per executed test method describing the covered business
 * scenario and its result, plus a small summary at the end. This makes the
 * surefire console show which behaviours are covered (tampered token, expiry,
 * insufficient permission, concurrent login failures, ...) and how each case
 * ended.
 *
 * <p>The simple test method name (snake/camel case) is rendered verbatim, so
 * descriptive method names read directly as a coverage list.
 */
public class BusinessCoverageTestListener implements TestExecutionListener {

    private static final Logger log = LoggerFactory.getLogger("BUSINESS_COVERAGE");

    private final AtomicInteger passed = new AtomicInteger();
    private final AtomicInteger failed = new AtomicInteger();
    private final AtomicInteger skipped = new AtomicInteger();

    @Override
    public void executionFinished(TestIdentifier identifier, TestExecutionResult result) {
        if (!identifier.isTest()) {
            return;
        }
        String scenario = humanize(identifier.getDisplayName());
        result.getThrowable().ifPresentOrElse(
                throwable -> {
                    failed.incrementAndGet();
                    log.info("[业务用例][FAIL] {} | 原因: {}", scenario,
                            throwable.getClass().getSimpleName());
                },
                () -> {
                    passed.incrementAndGet();
                    log.info("[业务用例][PASS] {}", scenario);
                });
    }

    @Override
    public void executionSkipped(TestIdentifier identifier, String reason) {
        if (identifier.isTest()) {
            skipped.incrementAndGet();
            log.info("[业务用例][SKIP] {} | 原因: {}", humanize(identifier.getDisplayName()),
                    reason == null ? "" : reason);
        }
    }

    @Override
    public void testPlanExecutionFinished(
            org.junit.platform.launcher.TestPlan testPlan) {
        log.info("========== 业务用例汇总: 通过={}, 失败={}, 跳过={} ==========",
                passed.get(), failed.get(), skipped.get());
    }

    private static String humanize(String name) {
        // JUnit's default display name for a method is the method name.
        return name.replace('_', ' ');
    }
}
