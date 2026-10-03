package com.github.feng111627.springauthaccesscontroljava.tests.support;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestExecutionExceptionHandler;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * 统一测试日志：
 * <ul>
 *   <li>每个测试类开始时打印“业务覆盖模块”标题；</li>
 *   <li>每条用例打印编号、用例名、结果（PASS/FAIL）与失败原因；</li>
 *   <li>类结束时打印通过/失败统计。</li>
 * </ul>
 * 通过 ServiceLoader（META-INF/services）自动对全部测试生效。
 */
public class BusinessTestLogger implements BeforeAllCallback, BeforeTestExecutionCallback,
        AfterTestExecutionCallback, AfterAllCallback, TestExecutionExceptionHandler {

    private static final String GREEN = "\u001B[32m";
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN = "\u001B[36m";
    private static final String RESET = "\u001B[0m";

    private static final ExtensionContext.Namespace NS =
            ExtensionContext.Namespace.create(BusinessTestLogger.class);

    private record Counters(AtomicInteger index, AtomicInteger passed, AtomicInteger failed) {
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(NS);
        store.put("counters", new Counters(new AtomicInteger(), new AtomicInteger(), new AtomicInteger()));
        System.out.printf("%n%s================ 业务测试模块: %s ================%s%n",
                CYAN, context.getRequiredTestClass().getSimpleName(), RESET);
    }

    @Override
    public void beforeTestExecution(ExtensionContext context) {
        int index = classCounters(context).index().incrementAndGet();
        System.out.printf("  [%02d] 开始: %s%n", index, context.getDisplayName());
    }

    @Override
    public void afterTestExecution(ExtensionContext context) {
        if (context.getExecutionException().isEmpty()) {
            Counters counters = classCounters(context);
            counters.passed().incrementAndGet();
            System.out.printf("  [%02d] %sPASS%s  %s%n",
                    counters.index().get(), GREEN, RESET, context.getDisplayName());
        }
    }

    @Override
    public void handleTestExecutionException(ExtensionContext context, Throwable throwable) throws Throwable {
        Counters counters = classCounters(context);
        counters.failed().incrementAndGet();
        System.out.printf("  [%02d] %sFAIL%s  %s%n         原因: %s: %s%n",
                counters.index().get(), RED, RESET, context.getDisplayName(),
                throwable.getClass().getSimpleName(), throwable.getMessage());
        throw throwable;
    }

    @Override
    public void afterAll(ExtensionContext context) {
        Counters counters = classCounters(context);
        int failed = counters.failed().get();
        int passed = counters.passed().get();
        String color = failed == 0 ? GREEN : YELLOW;
        System.out.printf("%s模块小结 %s: 共 %d 条, 通过 %d, 失败 %d%s%n",
                color, context.getRequiredTestClass().getSimpleName(),
                passed + failed, passed, failed, RESET);
    }

    private Counters classCounters(ExtensionContext context) {
        // 从当前上下文沿父链上溯，找到 beforeAll 存放计数器的类级上下文
        ExtensionContext current = context;
        while (current != null) {
            Counters counters = current.getStore(NS).get("counters", Counters.class);
            if (counters != null) {
                return counters;
            }
            current = current.getParent().orElse(null);
        }
        throw new IllegalStateException("找不到测试类计数器（beforeAll 是否执行）");
    }
}
