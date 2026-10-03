# Spring Boot 身份认证与访问控制（本地可运行）

一个不依赖外部安全框架的最小但完整的认证/鉴权实现：登录签发 **访问令牌（access token）** 与
**刷新令牌（refresh token）**，令牌异常、登录异常、权限异常都返回**确定且可区分**的结果；
包含登录失败限流与短时锁定，且并发下计数准确。所有数据保存在进程内存中，无需数据库。

- Java 21 语法级别 / Spring Boot 3.4.x / Spring Web
- 令牌：自实现 `base64url(header).base64url(payload).base64url(HMAC-SHA256)` 签名（JDK 原生，无第三方 JWT 库）
- 密码：PBKDF2-HMAC-SHA256（每口令独立盐、常量时间比较）

---

## 1. 快速开始

```bash
# 编译 + 全量单测（离线环境亦可，依赖已在本地 Maven 缓存）
mvn test

# 打包并以可执行 jar 运行
mvn package -DskipTests
java -jar target/spring-auth-access-control-java-1.0-SNAPSHOT.jar --server.port=8080
```

启动时自动播种 4 个账号，密码均为 `Passw0rd!`（可用 `--app.users.demo.password=xxx` 覆盖）：

| 用户名   | 角色    | 状态   |
|----------|---------|--------|
| admin    | ADMIN   | 启用   |
| editor   | EDITOR  | 启用   |
| viewer   | VIEWER  | 启用   |
| disabled | VIEWER  | 禁用   |

登录：

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"editor","password":"Passw0rd!"}'
# => accessToken / refreshToken / tokenType=Bearer / 两个 expiresInMillis
```

---

## 2. HTTP 接口

| 方法 & 路径                    | 鉴权要求                         | 说明                       |
|--------------------------------|----------------------------------|----------------------------|
| `GET  /api/public/ping`        | 无                               | 公开接口                   |
| `POST /api/auth/login`         | 无                               | 登录，返回令牌对           |
| `POST /api/auth/refresh`       | body 中携带 refresh token        | 刷新（**令牌轮换**）       |
| `POST /api/auth/logout`        | body 中携带 refresh token        | 吊销 refresh token，返回 204 |
| `GET  /api/me`                 | `@RequireAuth`：任意有效登录     | 返回实时身份/权限          |
| `GET  /api/admin/stats`        | `@RequireRole("ADMIN")`          | 角色受限                   |
| `GET  /api/articles/publish`   | `@RequirePermission("article:publish")` | 细粒度权限受限       |

受保护接口使用标准请求头：`Authorization: Bearer <accessToken>`。

### 统一错误体

所有错误都返回稳定的机器码 `code` 与可读 `message`：

```json
{ "code": "TOKEN_SIGNATURE_INVALID",
  "message": "Token signature is invalid (the token was tampered with)",
  "timestamp": "2026-10-03T15:33:05.635Z" }
```

---

## 3. 令牌生命周期与失败原因

### 3.1 结构与载荷

令牌格式为三段式 `header.payload.signature`，载荷字段：

| 字段    | 含义                                                        |
|---------|-------------------------------------------------------------|
| `sub`   | 用户名（令牌只携带**身份**，不携带权限）                    |
| `type`  | `ACCESS` 或 `REFRESH`                                       |
| `iat`   | 签发时间（毫秒）                                            |
| `exp`   | 过期时间（毫秒）                                            |
| `epoch` | 签发时账号的 **令牌纪元**（见 §5）                          |
| `jti`   | 每个令牌唯一 ID（refresh 轮换/吊销以此为准）                |

默认有效期（`application.properties` 可调）：access 5 分钟、refresh 60 分钟。

### 3.2 校验顺序与可区分失败码

校验严格按固定顺序进行，每种失败对应唯一错误码，**绝不合并成一个笼统的“token 无效”**：

| 顺序 | 判定                                   | 错误码                     | HTTP |
|------|----------------------------------------|----------------------------|------|
| 1    | 缺失/分段不对/Base64 无法解析          | `TOKEN_MALFORMED`          | 401  |
| 2    | HMAC 签名不匹配（**payload 或签名被篡改**） | `TOKEN_SIGNATURE_INVALID` | 401  |
| 3    | 当前时间 `>= exp`（**过期**）          | `TOKEN_EXPIRED`            | 401  |
| 4    | 令牌类型与使用场景不符（**类型用错**） | `TOKEN_WRONG_TYPE`         | 401  |
| 5    | refresh 的 `jti` 已被轮换/登出吊销     | `TOKEN_REVOKED`            | 401  |
| 6    | 账号当前已禁用                         | `TOKEN_USER_DISABLED`      | 401  |
| 7    | `epoch` 与账号当前纪元不一致（**账号变更**） | `TOKEN_STALE_EPOCH`    | 401  |

要点：

- **篡改 vs 过期 vs 类型用错** 三者通过 `SIGNATURE_INVALID / EXPIRED / WRONG_TYPE` 明确区分；
  过期判定先于类型判定（一个既过期又用错类型的令牌统一报“过期”，结果仍确定）。
- 用 **refresh token 访问业务接口**，或用 **access token 调刷新接口**，都得到 `TOKEN_WRONG_TYPE`。
- 签名比较使用常量时间比较（`MessageDigest.isEqual`）。

### 3.3 刷新轮换与登出语义（明确且前后一致）

- 每次 `/api/auth/refresh` 都签发**全新令牌对**，并立即吊销本次使用的 refresh token；
  旧 refresh token 再次使用 → `TOKEN_REVOKED`（即使它本身尚未过期）。
- `/api/auth/logout` 吊销传入的 refresh token；access token 不做服务端注销，依赖其短有效期自然失效。
- access token 的权限**永远实时读取**（见下节），因此登出后即使 access token 尚在几分钟有效期内，
  其能做的事也只等于“该账号此刻仍拥有的权限”；账号被禁用或权限被改时，旧 access token 会立即被拒。

---

## 4. 权限模型（角色 + 细粒度权限）

- 令牌只证明“你是谁”，**角色/权限/启用状态全部在每次请求时从存储实时读取**，不信任令牌内的快照。
- 角色到权限的并集映射（`Role` 枚举）：
  - `ADMIN`  → `article:publish`, `article:read`, `admin:stats`
  - `EDITOR` → `article:publish`, `article:read`
  - `VIEWER` → `article:read`
  - 用户还可被直接授予额外的细粒度权限；最终权限 = 角色权限 ∪ 直接权限。
- 方法注解：`@RequireAuth`（登录即可）、`@RequireRole("ADMIN")`、`@RequirePermission("article:publish")`。
- **未认证与权限不足严格区分**：
  - 没带令牌 / 令牌任何一关校验失败 → **401**（身份都无法确立）；
  - 身份有效但缺角色或缺权限 → **403 `ACCESS_DENIED`**，消息明确指出缺的是哪个角色/权限。

### 账号状态/权限变化后，已签发令牌的生效语义（token epoch）

每个账号有一个单调递增的 `tokenEpoch`，令牌签发时嵌入当时值。凡是

- 启用/禁用状态变化、
- 角色集合变化、
- 权限集合变化，

都会使 `tokenEpoch + 1`。请求时若令牌内的 epoch 与账号当前值不同 → 立即 401 `TOKEN_STALE_EPOCH`，
必须重新登录拿到新 epoch 的令牌。因此：

- 权限被收回 → 旧令牌**立刻**失去该权限（而不是等到过期）；
- 权限被授予 → 需重新登录获得携带新 epoch 的令牌后生效；
- 账号禁用 → 旧令牌得到 `TOKEN_USER_DISABLED`；重新启用后，旧令牌因 epoch 仍旧而得 `STALE_EPOCH`，
  仍需重新登录。语义前后一致：**令牌只在“签发时的账号版本”下有效**。

---

## 5. 登录限流与短时锁定

登录前置两道**相互独立、结果可区分**的闸门（均按“用户名”维度统计，未知用户名也同样统计，
避免账号探测）：

| 机制 | 触发条件（默认） | 失败结果 | HTTP |
|------|------------------|----------|------|
| 凭据错误 | 用户名不存在或密码错 | `LOGIN_BAD_CREDENTIALS` | 401 |
| 账号锁定 | 同一用户名连续失败 `max-failures=5` 次 | `LOGIN_ACCOUNT_LOCKED`（锁定 `lock-millis=5 分钟`，消息含剩余毫秒） | 423 |
| 滑动窗口限流 | `window-millis=60s` 窗口内失败达到 `max-attempts-per-window=10` 次 | `LOGIN_RATE_LIMITED`（消息含建议重试等待毫秒） | 429 |
| 账号禁用 | 密码正确但账号被禁用 | `LOGIN_ACCOUNT_DISABLED`（不计入失败次数，不发令牌） | 401 |

规则细节：

- 闸门在密码校验**之前**判定：锁定/限流期间不会泄露“密码对不对”。
- 连续失败达到阈值即锁定；锁定期内连正确密码也返回 `ACCOUNT_LOCKED`。
- 锁定到期后连续失败计数归零，可重新尝试；**滑动窗口独立保留**，因此短时间跨锁定周期持续爆破会得到 `RATE_LIMITED`。
- 登录成功立即清空该用户名的所有计数。
- 窗口限流与锁定同时满足时，限流优先（`RATE_LIMITED`），两类结果始终可分辨。

### 并发正确性

- 每个用户名持有独立的计数状态（`LoginAttemptState`），其所有方法在自身监视器上 `synchronized`；
  不同用户名完全并行。
- 登录流程在**每用户名锁**内把“闸门检查 → 密码校验 → 结果计数”作为一个原子决策，
  消除 check-then-act 竞争。因此 N 个并发错误密码恰好计为 N 次：
  第 5 次返回 `BAD_CREDENTIALS` 并触发锁定，第 6 次起全部返回 `ACCOUNT_LOCKED`，
  计数不会丢失、重复或互相覆盖。单测以 32 线程断言了这一点。

---

## 6. 本地验证方法

### 6.1 单元/集成测试

```bash
mvn test
```

- 共 46 个用例，全部通过。测试运行时控制台会逐条打印
  `[业务用例][PASS|FAIL] <场景描述>`，结尾打印
  `========== 业务用例汇总: 通过=N, 失败=M, 跳过=K ==========`，
  可直接看出覆盖了哪些业务及每个用例结果（由 `BusinessCoverageTestListener` 输出）。

覆盖矩阵：

| 测试类 | 覆盖业务 |
|--------|----------|
| `TokenServiceTest` | 合法令牌、payload/签名篡改、异密钥伪造、畸形令牌、access/refresh 过期、类型用错、过期优先于类型 |
| `LoginConcurrencyTest` | 错误密码计数、锁定触发与解除、成功清零、滑动窗口限流、未知用户、禁用账号、**32 线程并发失败恰好计数**、多用户并发互不串扰 |
| `AuthFlowIntegrationTest` | HTTP 登录、无令牌/篡改/错类型、刷新轮换重放吊销、登出吊销、权限/角色变更的 epoch 失效、禁用即失效、重新登录恢复 |
| `AccessControlIntegrationTest` | 公开接口、匿名 401、已认证权限不足 403、角色门、权限门、权限并集、仅认证接口 |

只跑某一类：

```bash
mvn test -Dtest=TokenServiceTest
mvn test -Dtest=LoginConcurrencyTest
mvn test -Dtest=AuthFlowIntegrationTest,AccessControlIntegrationTest
```

### 6.2 curl 手工验证（服务启动后）

```bash
B=http://localhost:8080

# 登录拿令牌
TOK=$(curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"Passw0rd!"}')
A=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin)['accessToken'])")

curl -s $B/api/me                                              # 401 TOKEN_MALFORMED
curl -s -H "Authorization: Bearer $A" $B/api/me               # 200
curl -s -H "Authorization: Bearer $A" $B/api/admin/stats      # 403 ACCESS_DENIED

# 连续错误密码：前 5 次 401 LOGIN_BAD_CREDENTIALS，第 6 次 423 LOGIN_ACCOUNT_LOCKED
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $B/api/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"viewer","password":"bad"}'
done
```

---

## 7. 配置项（`src/main/resources/application.properties`）

| 配置 | 默认值 | 说明 |
|------|--------|------|
| `app.security.token-secret` | 内置开发密钥 | HMAC 密钥，至少 32 字节；生产必须覆盖 |
| `app.security.access-token-ttl-millis` | 300000 | access token 有效期 |
| `app.security.refresh-token-ttl-millis` | 3600000 | refresh token 有效期 |
| `app.security.pbkdf2-iterations` | 120000 | PBKDF2 迭代次数（测试中可降低以提速） |
| `app.login.max-failures` | 5 | 触发账号锁定的连续失败次数 |
| `app.login.lock-millis` | 300000 | 锁定时长 |
| `app.login.max-attempts-per-window` | 10 | 滑动窗口内最大失败次数 |
| `app.login.window-millis` | 60000 | 滑动窗口长度 |
| `app.users.demo.password` | `Passw0rd!` | 播种演示账号的统一密码 |

> 说明：本实现面向“本地可运行/教学演示”，令牌密钥、用户与计数均保存在进程内存中，
> 重启即重置；接入生产时应替换为持久化用户库、外部密钥管理与集中式限流存储。
